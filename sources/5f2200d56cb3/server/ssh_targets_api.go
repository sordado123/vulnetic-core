package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"golang.org/x/crypto/ssh"
	"net/http"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/sshexec"
	"github.com/sordado123/vulnetic/vault"
)

// ---------- SSH targets (Fase B, Modo A) ----------

func (s *Server) listSSHTargets(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	targets, err := pg.ListSSHTargets(accountID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, target := range targets {
		target.AgentConnected = s.agentConnected(accountID, target.ID)
	}
	writeJSON(w, 200, map[string]any{"targets": targets})
}

func (s *Server) getSSHTarget(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid ssh target id")
		return
	}
	target, err := pg.GetSSHTarget(accountID, id)
	if err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	target.AgentConnected = s.agentConnected(accountID, target.ID)
	writeJSON(w, 200, target)
}

type createSSHTargetReq struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}

// createSSHTarget generates a fresh ed25519 keypair server-side (never
// accepts an uploaded private key, see docs/saas-blueprint.html Fase B),
// encrypts it under the account's DEK, and persists it. The response's
// public_key_openssh is what sshTargetInstallCommand turns into a
// copy-pasteable snippet; the private key is never sent back, ever.
func (s *Server) createSSHTarget(w http.ResponseWriter, r *http.Request) {
	if config.SaaSMode() {
		writeErr(w, 409, "use a temporary execution agent instead of inbound SSH")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	var req createSSHTargetReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	req.Username = strings.TrimSpace(req.Username)
	if req.Name == "" || req.Host == "" || req.Username == "" {
		writeErr(w, 400, "name, host and username are required")
		return
	}
	if req.Port <= 0 {
		req.Port = 22
	}
	if req.Port > 65535 || strings.ContainsAny(req.Host, " /\\\r\n\t") || strings.ContainsAny(req.Username, " /\\\r\n\t") {
		writeErr(w, 400, "invalid SSH host, username or port")
		return
	}

	dek, err := pg.GetOrCreateAccountDEK(accountID, s.vaultKey)
	if err != nil {
		writeErr(w, 500, "vault: "+err.Error())
		return
	}
	comment := fmt.Sprintf("vulnetic-%d-%s", accountID, req.Name)
	kp, err := sshexec.GenerateKeypair(comment)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sealed, err := vault.Seal(dek, kp.PrivateKeyPEM)
	if err != nil {
		writeErr(w, 500, "vault: "+err.Error())
		return
	}

	target, err := pg.CreateSSHTarget(accountID, req.Name, req.Host, req.Port, req.Username,
		sealed.Ciphertext, sealed.Nonce, kp.PublicKeyOpenSSH, kp.Fingerprint)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, target)
}

func (s *Server) deleteSSHTarget(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid ssh target id")
		return
	}
	target, err := pg.GetSSHTarget(accountID, id)
	if err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	if target.Transport == "agent" {
		if err = pg.RevokeExecutionAgent(r.Context(), accountID, id); err != nil {
			writeErr(w, 503, "could not persist executor revocation")
			return
		}
	}
	if err := s.revokeTargetSessions(accountID, id); err != nil {
		writeErr(w, 503, "Unable to pause executor tasks; retry revocation")
		return
	}
	if err := pg.DeleteSSHTarget(accountID, id); err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// sshTargetInstallCommand returns the one-liner the account runs on their
// own VPS to authorize Vulnetic's generated public key. Deliberately not a
// "curl | sh" (that pattern belongs to Modo B's agent-binary installer,
// which does not exist yet) — this only appends a public key, so there is
// no script-hosting/fetch surface to abuse.
func (s *Server) sshTargetInstallCommand(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid ssh target id")
		return
	}
	target, err := pg.GetSSHTarget(accountID, id)
	if err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	cmd := fmt.Sprintf(
		`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo %s >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
		shellQuote(target.PublicKeyOpenSSH),
	)
	writeJSON(w, 200, map[string]any{"command": cmd})
}

// validateSSHTarget decrypts the stored private key, dials the target, and
// runs a harmless no-op command — same health-check shape as pgRefreshMCP's
// UpdateMCPHealth for MCP servers (db/config.go).
func (s *Server) validateSSHTarget(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid ssh target id")
		return
	}
	target, err := pg.GetSSHTarget(accountID, id)
	if err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	preflight, runErr := s.sshPreflight(ctx, accountID, target.ID)
	if runErr != nil {
		_ = pg.UpdateSSHTargetHealth(accountID, id, false, runErr.Error())
		writeErr(w, 502, runErr.Error())
		return
	}
	if err := pg.SaveSSHPreflight(accountID, id, preflight); err != nil {
		writeErr(w, 503, "Preflight could not be persisted")
		return
	}
	if err := pg.UpdateSSHTargetHealth(accountID, id, true, ""); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "preflight": preflight})
}

func (s *Server) probeSSHHostKey(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid target")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	target, err := pg.GetSSHTarget(accountID, id)
	if err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	key, fingerprint, err := sshexec.ProbeHostKey(target.Host, target.Port)
	if err != nil {
		writeErr(w, 502, "Unable to obtain SSH host key")
		return
	}
	writeJSON(w, 200, map[string]any{"host_key": key, "fingerprint": fingerprint, "confirmed": target.HostKey == key})
}

func (s *Server) confirmSSHHostKey(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid target")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	var req struct {
		HostKey string `json:"host_key"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(req.HostKey))
	if err != nil || len(rest) > 0 {
		writeErr(w, 400, "invalid SSH host key")
		return
	}
	if _, err := pg.GetSSHTarget(accountID, id); err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	if err := s.revokeTargetSessions(accountID, id, false); err != nil {
		writeErr(w, 503, "Unable to pause executor tasks; retry revocation")
		return
	}
	if err := pg.ConfirmSSHHostKey(accountID, id, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))); err != nil {
		sshTargetLookupErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) revokeTargetSessions(accountID, id int64, permanent ...bool) error {
	s.remoteMu.Lock()
	owner := remoteOwner{accountID, id}
	if s.revokedTargets == nil {
		s.revokedTargets = make(map[remoteOwner]bool)
	}
	if len(permanent) == 0 || permanent[0] {
		s.revokedTargets[owner] = true
	}
	for ex, key := range s.remoteExecutors {
		if key == owner {
			_ = ex.Close()
			delete(s.remoteExecutors, ex)
		}
	}
	if entry := s.agentConnections[owner]; entry != nil {
		if entry.client != nil {
			_ = entry.client.Close()
		}
		if entry.gatewayRef != "" && s.gateway != nil {
			s.gateway.Revoke(entry.gatewayRef)
		}
		delete(s.agentConnections, owner)
	}
	s.remoteMu.Unlock()
	return s.pauseTargetTasks(accountID, id)
}

func (s *Server) pauseTargetTasks(accountID, id int64) error {
	var pauseErrors []error
	for _, task := range s.m.List() {
		targetID := task.lifecycleSnapshot().SSHTargetID
		if task.AccountID == accountID && targetID != nil && *targetID == id {
			s.cancelTaskChat(task.ID, nil)
			s.evictTaskAgents(task.ID)
			lifecycle := task.lifecycleSnapshot()
			if !lifecycle.Paused && !isTerminalStatus(lifecycle.Status) {
				if _, err := s.applyTaskControl(task, "pause"); err != nil {
					pauseErrors = append(pauseErrors, err)
				}
			}
		}
	}
	return errors.Join(pauseErrors...)
}

// updateTaskSSHTarget replaces only the binding of an idle, paused/terminal task.
// Lifecycle admission and task chat stay excluded until the old bundle is evicted.
func (s *Server) updateTaskSSHTarget(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		SSHTargetID *int64 `json:"ssh_target_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid executor configuration")
		return
	}
	s.concMu.Lock()
	defer s.concMu.Unlock()
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	current, exists := s.m.Task(t.ID)
	if !exists || current != t || s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	state := t.lifecycleSnapshot()
	if state.Queued || (!state.Paused && !isTerminalStatus(state.Status)) {
		writeErr(w, 409, "pause the task before changing its VPS")
		return
	}
	if s.chatBusy[t.ID] || s.engine.inflightCount(t.ID) > 0 || s.engine.ActiveLLMCalls(t.ID) > 0 {
		writeErr(w, 409, "wait for task operations and the main-agent turn to stop before changing its VPS")
		return
	}
	if req.SSHTargetID == nil && config.SaaSMode() {
		writeErr(w, 400, "select a connected VPS owned by this account")
		return
	}
	if req.SSHTargetID != nil {
		if _, err := s.m.pg.GetSSHTarget(t.AccountID, *req.SSHTargetID); err != nil {
			sshTargetLookupErr(w, err)
			return
		}
		if _, err := s.verifiedTarget(t.AccountID, *req.SSHTargetID); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	if err := s.m.SetTaskSSHTarget(t.AccountID, t.ID, req.SSHTargetID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.taskFileRestoreJobs.Delete(t.ID)
	s.evictTaskAgents(t.ID)
	writeJSON(w, 200, map[string]any{"id": t.ID, "ssh_target_id": req.SSHTargetID})
}

func sshTargetLookupErr(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrSSHTargetNotFound) {
		writeErr(w, 404, "ssh target not found")
		return
	}
	writeErr(w, 500, err.Error())
}
