package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/internal/runstate"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type gatewayOwner struct {
	created  time.Time
	owner    remoteOwner
	hash     []byte
	expires  time.Time
	source   string
	platform string
}

func (s *Server) initGateway() {
	address := os.Getenv("VULNETIC_GATEWAY_URL")
	if address == "" {
		return
	}
	token, err := os.ReadFile(os.Getenv("VULNETIC_GATEWAY_TOKEN_FILE"))
	if err != nil {
		panic("gateway control credential unavailable")
	}
	client, err := agentgateway.NewClient(address, strings.TrimSpace(string(token)))
	if err != nil {
		panic(err)
	}
	s.gateway = client
	s.gatewayOwners = make(map[string]gatewayOwner)
	go client.Run(s.ctx, s.gatewayEvent, s.gatewayDisconnected)
}
func (s *Server) gatewayDisconnected() {
	s.remoteMu.Lock()
	owners := make([]remoteOwner, 0, len(s.agentConnections))
	for owner, entry := range s.agentConnections {
		if entry.gatewayRef != "" {
			owners = append(owners, owner)
			delete(s.agentConnections, owner)
		}
	}
	clear(s.gatewayOwners)
	for ex, owner := range s.remoteExecutors {
		for _, disconnected := range owners {
			if owner == disconnected {
				ex.Disconnect()
				break
			}
		}
	}
	s.remoteMu.Unlock()
	for _, owner := range owners {
		_ = s.m.pg.UpdateSSHTargetHealth(owner.accountID, owner.targetID, false, "Executor gateway disconnected; reconnecting until access deadline")
		_ = s.pauseTargetTasks(owner.accountID, owner.targetID)
	}
}
func (s *Server) gatewayEvent(ctx context.Context, m agentgateway.Message) agentgateway.Message {
	denied := func() agentgateway.Message {
		return agentgateway.Message{Error: "operation unavailable, expired or revoked"}
	}
	if ctx.Err() != nil {
		return agentgateway.Message{Temporary: true, Error: "control temporarily unavailable"}
	}
	switch m.Type {
	case "enroll":
		if len(m.Hash) != sha256.Size || m.Request == nil || len(m.Request.HostKey) > 8192 || !agentUsername.MatchString(m.Request.Username) {
			return denied()
		}
		if m.Request.Platform != "" && m.Request.Platform != "linux" && m.Request.Platform != "windows" {
			return denied()
		}
		token, hash, err := agentToken()
		if err != nil {
			return denied()
		}
		target, lifetime, err := s.m.pg.RedeemAgentEnrollment(ctx, m.Hash, hash, m.Request.HostKey, m.Request.Username, m.Request.Platform)
		if err != nil {
			return denied()
		}
		if err = s.m.pg.RecordAudit(target.AccountID, 0, "AGENT_ENROLL", fmt.Sprintf("/executors/%d", target.ID), 200); err != nil {
			_ = s.m.pg.RevokeExecutionAgent(ctx, target.AccountID, target.ID)
			return denied()
		}
		return agentgateway.Message{Enrollment: agentEnrollment(token, target, lifetime)}
	case "authenticate":
		if len(m.Hash) != sha256.Size || net.ParseIP(m.SourceIP) == nil {
			return denied()
		}
		if platformpolicy.CheckExecutorSource(m.SourceIP) != nil {
			return denied()
		}
		accountID, targetID, err := s.m.pg.AgentIdentity(ctx, m.Hash)
		if err != nil {
			if errors.Is(err, db.ErrAgentLease) {
				return denied()
			}
			return agentgateway.Message{Temporary: true, Error: "credential lookup unavailable"}
		}
		target, err := s.m.pg.GetSSHTarget(accountID, targetID)
		if err != nil {
			return agentgateway.Message{Temporary: true, Error: "executor lookup unavailable"}
		}
		if !target.AgentLeaseCurrent(time.Now()) {
			return denied()
		}
		key, err := s.targetPrivateKey(target)
		if err != nil {
			return agentgateway.Message{Temporary: true, Error: "executor identity unavailable"}
		}
		ref := agentgateway.ID()
		owner := remoteOwner{accountID, targetID}
		s.remoteMu.Lock()
		for old, pending := range s.gatewayOwners {
			if time.Now().After(pending.expires) || (s.agentConnections[pending.owner] == nil && time.Since(pending.created) > 15*time.Second) {
				delete(s.gatewayOwners, old)
			}
		}
		pendingCount := 0
		for _, pending := range s.gatewayOwners {
			if pending.owner.accountID == accountID {
				pendingCount++
			}
		}
		if len(s.gatewayOwners) >= 32 || pendingCount >= 6 {
			s.remoteMu.Unlock()
			return denied()
		}
		s.gatewayOwners[ref] = gatewayOwner{created: time.Now(), owner: owner, hash: append([]byte(nil), m.Hash...), expires: *target.AgentExpiresAt, source: m.SourceIP, platform: target.OperatingSystem()}
		s.remoteMu.Unlock()
		return agentgateway.Message{Identity: &agentgateway.Identity{Ref: ref, Username: target.Username, PrivateKey: key, HostKey: target.HostKey, ExpiresAt: *target.AgentExpiresAt}}
	case "connected", "disconnected", "validate":
		s.remoteMu.Lock()
		lease, exists := s.gatewayOwners[m.Ref]
		s.remoteMu.Unlock()
		if !exists {
			return denied()
		}
		if m.Type == "disconnected" {
			s.gatewayAgentDisconnected(m.Ref, lease.owner)
			return agentgateway.Message{}
		}
		accountID, targetID, err := s.m.pg.AgentIdentity(ctx, lease.hash)
		if err != nil || accountID != lease.owner.accountID || targetID != lease.owner.targetID || !time.Now().Before(lease.expires) {
			s.gateway.Revoke(m.Ref)
			return denied()
		}
		if m.Type == "validate" {
			return agentgateway.Message{}
		}
		if m.SourceIP != lease.source {
			return denied()
		}
		if err = s.m.pg.RecordExecutorOrigin(ctx, m.SourceIP, lease.expires.Add(24*time.Hour)); err != nil {
			return denied()
		}
		s.remoteMu.Lock()
		active := 0
		for owner := range s.agentConnections {
			if owner.accountID == accountID {
				active++
			}
		}
		if s.revokedTargets[lease.owner] || s.agentConnections[lease.owner] != nil || active >= 3 {
			s.remoteMu.Unlock()
			return denied()
		}
		if s.agentConnections == nil {
			s.agentConnections = make(map[remoteOwner]*agentConnection)
		}
		s.agentConnections[lease.owner] = &agentConnection{gatewayRef: m.Ref, platform: lease.platform}
		s.remoteMu.Unlock()
		if s.m.pg.RecordAudit(accountID, 0, "AGENT_CONNECT", fmt.Sprintf("/executors/%d", targetID), 200) != nil {
			s.gatewayAgentDisconnected(m.Ref, lease.owner)
			return denied()
		}
		go func() {
			check, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			defer cancel()
			result, err := s.sshPreflight(check, accountID, targetID)
			s.remoteMu.Lock()
			defer s.remoteMu.Unlock()
			entry := s.agentConnections[lease.owner]
			if entry == nil || entry.gatewayRef != m.Ref {
				return
			}
			if err != nil {
				_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, false, "Remote tools or workspace validation failed")
				return
			}
			if s.m.pg.SaveSSHPreflight(accountID, targetID, result) == nil {
				_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, true, "")
			}
		}()
		return agentgateway.Message{}
	}
	return denied()
}
func (s *Server) gatewayAgentDisconnected(ref string, owner remoteOwner) {
	s.remoteMu.Lock()
	delete(s.gatewayOwners, ref)
	entry := s.agentConnections[owner]
	if entry == nil || entry.gatewayRef != ref {
		s.remoteMu.Unlock()
		return
	}
	delete(s.agentConnections, owner)
	for ex, key := range s.remoteExecutors {
		if key == owner {
			ex.Disconnect()
		}
	}
	s.remoteMu.Unlock()
	_ = s.m.pg.UpdateSSHTargetHealth(owner.accountID, owner.targetID, false, "Executor disconnected; reconnecting until access deadline")
	_ = s.pauseTargetTasks(owner.accountID, owner.targetID)
	_ = s.m.pg.RecordAudit(owner.accountID, 0, "AGENT_DISCONNECT", fmt.Sprintf("/executors/%d", owner.targetID), 200)
}
func (s *Server) newRemoteExecutor(accountID, targetID int64, directory string) (executor *sshexec.LazyExecutor) {
	defer func() { executor.TargetID = targetID; executor.AccountID = accountID }()
	if config.SaaSMode() {
		target, err := s.m.pg.ForAccount(accountID).GetSSHTarget(accountID, targetID)
		if err != nil || target == nil || target.AgentExpiresAt == nil || s.gateway == nil {
			return sshexec.NewTaskExecutor(func() (*ssh.Client, error) { return nil, agentgateway.ErrExecutorRevoked }, nil, directory)
		}
		expires, hostKey := *target.AgentExpiresAt, target.HostKey
		remote := s.gateway.ResolvingRemote(directory, func(ctx context.Context) (string, error) {
			return s.gatewayRefFor(ctx, remoteOwner{accountID, targetID}, expires, hostKey)
		})
		executor = sshexec.NewTransportExecutor(remote, directory)
		executor.Platform = target.OperatingSystem()
		return executor
	}
	return sshexec.NewTaskExecutor(s.dialTaskSSHTarget(accountID, targetID), s.enableSSHTrafficCapture(), directory)
}
func (s *Server) legacyAgentProxy() http.Handler {
	target, err := url.Parse(os.Getenv("VULNETIC_GATEWAY_PUBLIC_URL"))
	if err != nil || target.Host == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "executor gateway unavailable", 503) })
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "executor gateway unavailable", 503)
	}
	return proxy
}
func agentEnrollment(token string, target *db.SSHTarget, lifetime int) *reverseagent.Enrollment {
	return &reverseagent.Enrollment{RuntimeToken: token, ClientPublicKey: target.PublicKeyOpenSSH, LeaseSeconds: lifetime, ExpiresAt: *target.AgentExpiresAt}
}

// Wait only before a new operation, never replay a command or extend its original lease.
func (s *Server) gatewayRefFor(parent context.Context, owner remoteOwner, expires time.Time, hostKey string) (ref string, err error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	waited := false
	state := runstate.From(parent)
	phase := ""
	if state != nil {
		phase = state.Snapshot().Phase
	}
	defer func() {
		if waited {
			log.Printf("[gateway] event=executor_reconnect_wait_finished account=%d target=%d recovered=%t", owner.accountID, owner.targetID, err == nil)
			if err == nil {
				state.Phase(phase)
			}
		}
	}()
	for {
		if !time.Now().Before(expires) {
			return "", agentgateway.ErrExecutorExpired
		}
		s.remoteMu.Lock()
		revoked := s.revokedTargets[owner]
		entry := s.agentConnections[owner]
		var lease gatewayOwner
		var exists bool
		ref = ""
		if entry != nil {
			ref = entry.gatewayRef
			lease, exists = s.gatewayOwners[ref]
		}
		s.remoteMu.Unlock()
		if revoked || (exists && lease.owner != owner) {
			return "", agentgateway.ErrExecutorRevoked
		}
		if s.gateway != nil && s.gateway.Ready() && ref != "" && exists && lease.owner == owner {
			pg := s.m.pg.ForAccount(owner.accountID)
			target, e := pg.GetSSHTargetContext(ctx, owner.accountID, owner.targetID)
			if e != nil {
				if errors.Is(e, db.ErrSSHTargetNotFound) {
					return "", agentgateway.ErrExecutorRevoked
				}
				if parent.Err() != nil {
					return "", parent.Err()
				}
				return "", agentgateway.ErrGatewayUnavailable
			}
			if target.AgentExpiresAt == nil || !target.AgentExpiresAt.Equal(expires) || target.HostKey != hostKey {
				return "", agentgateway.ErrExecutorRevoked
			}
			if !target.AgentLeaseCurrent(time.Now()) {
				return "", agentgateway.ErrExecutorExpired
			}
			account, targetID, e := s.m.pg.AgentIdentity(ctx, lease.hash)
			if e != nil {
				if errors.Is(e, db.ErrAgentLease) {
					return "", agentgateway.ErrExecutorRevoked
				}
				return "", agentgateway.ErrGatewayUnavailable
			}
			if account != owner.accountID || targetID != owner.targetID {
				return "", agentgateway.ErrExecutorRevoked
			}
			s.remoteMu.Lock()
			current := s.agentConnections[owner]
			valid := !s.revokedTargets[owner] && current != nil && current.gatewayRef == ref
			s.remoteMu.Unlock()
			trustedProbe, _ := parent.Value(executorPreflightContextKey{}).(bool)
			// Customer operations keep both checks; only sshPreflight can issue this fixed metadata probe.
			if valid && ((target.Status == db.SSHTargetVerified && preflightComplete(target)) || trustedProbe) {
				return ref, nil
			}
		}
		if !waited {
			waited = true
			state.Phase("waiting_executor")
			log.Printf("[gateway] event=executor_reconnect_wait account=%d target=%d", owner.accountID, owner.targetID)
		}
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return "", parent.Err()
			}
			if !time.Now().Before(expires) {
				return "", agentgateway.ErrExecutorExpired
			}
			if s.gateway == nil || !s.gateway.Ready() {
				return "", agentgateway.ErrGatewayUnavailable
			}
			return "", agentgateway.ErrExecutorOffline
		case <-ticker.C:
		}
	}
}
