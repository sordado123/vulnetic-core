package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/sshexec"
)

type remoteOwner struct{ accountID, targetID int64 }

func (s *Server) verifiedTarget(accountID, targetID int64) (*db.SSHTarget, error) {
	target, err := s.m.pg.GetSSHTarget(accountID, targetID)
	if err != nil {
		return nil, fmt.Errorf("VPS not found")
	}
	if config.SaaSMode() && !target.AgentLeaseCurrent(time.Now()) {
		return nil, fmt.Errorf("connect a temporary executor with an active lease")
	}
	if config.SaaSMode() && !s.agentConnected(accountID, targetID) {
		return nil, fmt.Errorf("the temporary executor is disconnected")
	}
	if target.HostKey == "" || target.Status != db.SSHTargetVerified || (config.SaaSMode() && !preflightComplete(target)) {
		return nil, fmt.Errorf("confirm the SSH host key and validate this VPS")
	}
	return target, nil
}

func (s *Server) remoteExecutor(accountID, targetID int64, directory string) (*sshexec.LazyExecutor, func(), error) {
	if _, err := s.verifiedTarget(accountID, targetID); err != nil {
		return nil, nil, err
	}
	return s.trackRemoteExecutor(accountID, targetID, directory)
}

func (s *Server) trackRemoteExecutor(accountID, targetID int64, directory string) (*sshexec.LazyExecutor, func(), error) {
	ex := s.newRemoteExecutor(accountID, targetID, directory)
	owner := remoteOwner{accountID, targetID}
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.revokedTargets[owner] {
		return nil, nil, fmt.Errorf("VPS has been revoked; validate it again")
	}

	if s.remoteExecutors == nil {
		s.remoteExecutors = make(map[*sshexec.LazyExecutor]remoteOwner)
	}
	s.remoteExecutors[ex] = owner
	return ex, func() { _ = ex.Close(); s.remoteMu.Lock(); delete(s.remoteExecutors, ex); s.remoteMu.Unlock() }, nil
}

func (s *Server) remoteRequestContext(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	if !config.SaaSMode() {
		return r.Context(), func() {}, true
	}
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return nil, nil, false
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("ssh_target_id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "ssh_target_id is required for remote operations")
		return nil, nil, false
	}
	ex, closeExecutor, err := s.remoteExecutor(accountID, id, fmt.Sprintf(".vulnetic/accounts/%d/tool-tests", accountID))
	if err != nil {
		writeErr(w, 409, err.Error())
		return nil, nil, false
	}
	return agent.WithRunInfo(r.Context(), agent.RunInfo{AccountID: accountID, Executor: ex}), closeExecutor, true
}
