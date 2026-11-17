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
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
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
				_ = ex.Close()
				delete(s.remoteExecutors, ex)
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
			_ = ex.Close()
			delete(s.remoteExecutors, ex)
		}
	}
	s.remoteMu.Unlock()
	_ = s.m.pg.UpdateSSHTargetHealth(owner.accountID, owner.targetID, false, "Executor disconnected; reconnecting until access deadline")
	_ = s.pauseTargetTasks(owner.accountID, owner.targetID)
	_ = s.m.pg.RecordAudit(owner.accountID, 0, "AGENT_DISCONNECT", fmt.Sprintf("/executors/%d", owner.targetID), 200)
}
func (s *Server) newRemoteExecutor(accountID, targetID int64, directory string) (executor *sshexec.LazyExecutor) {
	defer func() { executor.TargetID = targetID }()
	if config.SaaSMode() {
		s.remoteMu.Lock()
		entry := s.agentConnections[remoteOwner{accountID, targetID}]
		ref := ""
		if entry != nil {
			ref = entry.gatewayRef
		}
		s.remoteMu.Unlock()
		if s.gateway != nil && ref != "" {
			executor = sshexec.NewTransportExecutor(s.gateway.Remote(ref, directory), directory)
			executor.Platform = entry.platform
			return executor
		}
		return sshexec.NewTaskExecutor(func() (*ssh.Client, error) {
			return nil, errors.New("execution_policy_unavailable: executor gateway unavailable")
		}, nil, directory)
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
