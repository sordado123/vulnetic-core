package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/agentassets"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
	"github.com/sordado123/vulnetic/vault"
	"golang.org/x/crypto/ssh"
)

type agentConnection struct {
	client     *ssh.Client
	gatewayRef string
	platform   string
}

func (s *Server) agentConnected(accountID, targetID int64) bool {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	owner := remoteOwner{accountID, targetID}
	return !s.revokedTargets[owner] && s.agentConnections[owner] != nil
}

func agentToken() (string, []byte, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(value)
	hash := sha256.Sum256([]byte(token))
	return token, hash[:], nil
}

func agentTokenHash(r *http.Request) ([]byte, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	hash := sha256.Sum256([]byte(token))
	return hash[:], true
}

func platformAgentURL() (string, error) {
	base := strings.TrimSpace(os.Getenv("VULNETIC_AGENT_PUBLIC_URL"))
	if base == "" {
		base = strings.TrimSpace(os.Getenv("VULNETIC_PUBLIC_URL"))
	}
	u, err := reverseagent.ValidateServerURL(base)
	if err != nil {
		return "", fmt.Errorf("the operator must configure the platform HTTPS enrollment URL")
	}
	return u.String(), nil
}

func (s *Server) executionAgentCommand(w http.ResponseWriter, target *db.SSHTarget, base, token string, lifetime int) {
	if target.OperatingSystem() == "windows" {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"target": target, "command": agentassets.WindowsInstallCommand(base, token, lifetime), "enrollment_valid_seconds": 300, "lease_seconds": lifetime})
		return
	}
	command := "curl --fail --silent --show-error --location " + shellQuote(base+"/agent/install.sh") + " | VULNETIC_SERVER_URL=" + shellQuote(base) + " VULNETIC_ENROLL_TOKEN=" + shellQuote(token) + " VULNETIC_LEASE_SECONDS=" + fmt.Sprint(lifetime) + " sh"
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"target": target, "command": command, "enrollment_valid_seconds": 300, "lease_seconds": lifetime})
}

func (s *Server) createExecutionAgent(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	base, err := platformAgentURL()
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	var body struct {
		Name     string `json:"name"`
		Lifetime int    `json:"lease_seconds"`
		Platform string `json:"platform"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decode(r, &body) != nil {
		writeErr(w, 400, "invalid executor configuration")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Platform == "" {
		body.Platform = "linux"
	}
	if body.Name == "" || len(body.Name) > 120 || body.Lifetime < 300 || body.Lifetime > 604800 || (body.Platform != "linux" && body.Platform != "windows") {
		writeErr(w, 400, "provide a name and a lifetime between 5 minutes and 7 days")
		return
	}
	token, hash, err := agentToken()
	if err != nil {
		writeErr(w, 503, "enrollment is unavailable")
		return
	}
	pair, err := sshexec.GenerateKeypair("temporary-agent")
	if err != nil {
		writeErr(w, 503, "executor identity is unavailable")
		return
	}
	dek, err := s.m.pg.GetOrCreateAccountDEK(accountID, s.vaultKey)
	if err != nil {
		writeErr(w, 503, "credential storage is unavailable")
		return
	}
	sealed, err := vault.Seal(dek, pair.PrivateKeyPEM)
	if err != nil {
		writeErr(w, 503, "credential storage is unavailable")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	target, err := pg.CreateExecutionAgent(r.Context(), accountID, body.Name, body.Lifetime, hash, sealed.Ciphertext, sealed.Nonce, pair.PublicKeyOpenSSH, pair.Fingerprint, body.Platform)
	if err != nil {
		writeErr(w, 503, "could not save the executor enrollment")
		return
	}
	s.executionAgentCommand(w, target, base, token, body.Lifetime)
}

func (s *Server) renewExecutionAgent(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 404, "executor not found")
		return
	}
	target, err := s.m.pg.GetSSHTarget(accountID, id)
	if err != nil || target.Transport != "agent" {
		writeErr(w, 404, "executor not found")
		return
	}
	base, err := platformAgentURL()
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	var body struct {
		Lifetime int    `json:"lease_seconds"`
		Platform string `json:"platform"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if decode(r, &body) != nil || body.Lifetime < 300 || body.Lifetime > 604800 || (body.Platform != "" && body.Platform != "linux" && body.Platform != "windows") {
		writeErr(w, 400, "choose a lifetime between 5 minutes and 7 days")
		return
	}
	if body.Platform == "" {
		body.Platform = target.OperatingSystem()
	}
	token, hash, err := agentToken()
	if err != nil {
		writeErr(w, 503, "enrollment is unavailable")
		return
	}
	if err = s.m.pg.ForAccount(accountID).RenewExecutionAgent(r.Context(), accountID, id, body.Lifetime, hash, body.Platform); err != nil {
		writeErr(w, 503, "could not renew enrollment")
		return
	}
	if err = s.revokeTargetSessions(accountID, id); err != nil {
		writeErr(w, 503, "could not pause executor tasks; retry enrollment")
		return
	}
	s.remoteMu.Lock()
	delete(s.revokedTargets, remoteOwner{accountID, id})
	s.remoteMu.Unlock()
	target, err = s.m.pg.GetSSHTarget(accountID, id)
	if err != nil {
		writeErr(w, 503, "executor unavailable")
		return
	}
	s.executionAgentCommand(w, target, base, token, body.Lifetime)
}

func (s *Server) allowAgentConnection(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.authLimits.allow("agent:"+host, 60, time.Now()) {
		writeErr(w, 429, "too many enrollment or connection attempts")
		return false
	}
	return true
}

func (s *Server) revokeExecutionAgent(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 404, "executor not found")
		return
	}
	target, err := s.m.pg.GetSSHTarget(accountID, id)
	if err != nil || target.Transport != "agent" {
		writeErr(w, 404, "executor not found")
		return
	}
	if err = s.m.pg.ForAccount(accountID).RevokeExecutionAgent(r.Context(), accountID, id); err != nil {
		writeErr(w, 503, "could not persist executor revocation")
		return
	}
	if err = s.revokeTargetSessions(accountID, id); err != nil {
		writeErr(w, 503, "could not pause executor tasks; retry revocation")
		return
	}
	if err = s.m.pg.UpdateSSHTargetHealth(accountID, id, false, "Agent access revoked; generate a new command to reconnect"); err != nil {
		writeErr(w, 503, "could not persist executor state")
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}

var agentUsername = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)

func (s *Server) enrollExecutionAgent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowAgentConnection(w, r) {
		return
	}
	hash, ok := agentTokenHash(r)
	if !ok {
		writeErr(w, 401, "invalid enrollment")
		return
	}
	var body reverseagent.EnrollmentRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if json.NewDecoder(r.Body).Decode(&body) != nil || !agentUsername.MatchString(body.Username) {
		writeErr(w, 400, "invalid executor identity")
		return
	}
	if body.Platform != "" && body.Platform != "linux" && body.Platform != "windows" {
		writeErr(w, http.StatusBadRequest, "unsupported executor platform")
		return
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(body.HostKey))
	if err != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		writeErr(w, 400, "invalid executor identity")
		return
	}
	token, runtimeHash, err := agentToken()
	if err != nil {
		writeErr(w, 503, "enrollment is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	target, lifetime, err := s.m.pg.RedeemAgentEnrollment(ctx, hash, runtimeHash, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), body.Username, body.Platform)
	if err != nil {
		writeErr(w, 401, "enrollment expired, revoked or already used")
		return
	}
	if err = s.m.pg.RecordAudit(target.AccountID, 0, "AGENT_ENROLL", fmt.Sprintf("/executors/%d", target.ID), 200); err != nil {
		_ = s.m.pg.RevokeExecutionAgent(ctx, target.AccountID, target.ID)
		writeErr(w, 503, "could not persist enrollment audit")
		return
	}
	writeJSON(w, 200, reverseagent.Enrollment{RuntimeToken: token, ClientPublicKey: target.PublicKeyOpenSSH, LeaseSeconds: lifetime, ExpiresAt: *target.AgentExpiresAt})
}

func (s *Server) targetPrivateKey(target *db.SSHTarget) ([]byte, error) {
	dek, err := s.m.pg.GetOrCreateAccountDEK(target.AccountID, s.vaultKey)
	if err != nil {
		return nil, err
	}
	return vault.Open(dek, vault.Sealed{Nonce: target.PrivateKeyNonce, Ciphertext: target.EncryptedPrivateKey})
}

func (s *Server) connectExecutionAgent(w http.ResponseWriter, r *http.Request) {
	if config.SaaSMode() {
		writeErr(w, 503, "executor gateway required")
		return
	}
	if !s.allowAgentConnection(w, r) {
		return
	}
	hash, ok := agentTokenHash(r)
	if !ok {
		writeErr(w, 401, "invalid agent credential")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	accountID, targetID, err := s.m.pg.AgentIdentity(ctx, hash)
	cancel()
	if err != nil {
		writeErr(w, 401, "agent access expired or was revoked")
		return
	}
	target, err := s.m.pg.GetSSHTarget(accountID, targetID)
	if err != nil || !target.AgentLeaseCurrent(time.Now()) {
		writeErr(w, 410, "agent lease ended")
		return
	}
	key, err := s.targetPrivateKey(target)
	if err != nil {
		writeErr(w, 503, "executor identity unavailable")
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }, HandshakeTimeout: 10 * time.Second}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(2 << 20)
	connection := &reverseagent.WebSocketConn{Conn: ws}
	defer connection.Close()
	client, err := sshexec.DialPinnedConn(connection, target.Username, key, target.HostKey)
	if err != nil {
		return
	}
	owner := remoteOwner{accountID, targetID}
	entry := &agentConnection{client: client, platform: target.OperatingSystem()}
	s.remoteMu.Lock()
	if s.agentConnections == nil {
		s.agentConnections = make(map[remoteOwner]*agentConnection)
	}
	active := 0
	for existing := range s.agentConnections {
		if existing.accountID == accountID {
			active++
		}
	}
	if s.revokedTargets[owner] || s.agentConnections[owner] != nil {
		s.remoteMu.Unlock()
		_ = client.Close()
		return
	}
	if active >= 3 {
		s.remoteMu.Unlock()
		_ = client.Close()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = s.m.pg.RevokeAgentConnection(cleanup, accountID, targetID, hash)
		done()
		_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, false, "Limit of 3 connected executors reached; revoke one and generate a new command")
		return
	}
	s.agentConnections[owner] = entry
	s.remoteMu.Unlock()
	defer func() {
		s.remoteMu.Lock()
		if s.agentConnections[owner] != entry {
			s.remoteMu.Unlock()
			return
		}
		_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, false, "Executor disconnected; reconnecting automatically until its access deadline")

		delete(s.agentConnections, owner)
		for ex, key := range s.remoteExecutors {
			if key == owner {
				_ = ex.Close()
				delete(s.remoteExecutors, ex)
			}
		}
		s.remoteMu.Unlock()
		_ = client.Close()
		_ = s.pauseTargetTasks(accountID, targetID)
		_ = s.m.pg.RecordAudit(accountID, 0, "AGENT_DISCONNECT", fmt.Sprintf("/executors/%d", targetID), 200)
	}()
	if err = s.m.pg.RecordAudit(accountID, 0, "AGENT_CONNECT", fmt.Sprintf("/executors/%d", targetID), 200); err != nil {
		_ = client.Close()
		return
	}
	lease, stop := context.WithDeadline(s.ctx, *target.AgentExpiresAt)
	defer stop()
	closeOnCancel := context.AfterFunc(lease, func() { _ = client.Close() })
	defer closeOnCancel()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lease.Done():
				return
			case <-ticker.C:
				check, done := context.WithTimeout(lease, 3*time.Second)
				a, id, e := s.m.pg.AgentIdentity(check, hash)
				done()
				if e != nil || a != accountID || id != targetID {
					_ = client.Close()
					return
				}
				ping := make(chan error, 1)
				go func() { _, _, e := client.SendRequest("keepalive@vulnetic", true, nil); ping <- e }()
				timeout := time.NewTimer(15 * time.Second)
				select {
				case e = <-ping:
					timeout.Stop()
					if e != nil {
						_ = client.Close()
						return
					}
				case <-timeout.C:
					_ = client.Close()
					return
				case <-lease.Done():
					timeout.Stop()
					return
				}
			}
		}
	}()
	go func() {
		preflightCtx, done := context.WithTimeout(lease, 30*time.Second)
		defer done()
		result, e := s.sshPreflight(preflightCtx, accountID, targetID)
		s.remoteMu.Lock()
		defer s.remoteMu.Unlock()
		if s.agentConnections[owner] != entry {
			return
		}
		if e != nil {
			_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, false, "Remote tools or workspace validation failed")
			return
		}
		if s.m.pg.SaveSSHPreflight(accountID, targetID, result) == nil {
			_ = s.m.pg.UpdateSSHTargetHealth(accountID, targetID, true, "")
		}
	}()
	_ = client.Wait()
}
