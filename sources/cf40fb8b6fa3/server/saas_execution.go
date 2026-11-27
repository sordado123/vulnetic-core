package server

import (
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"time"
)

func (s *Server) validateSaaSTask(t *Task) error {
	if !config.SaaSMode() {
		return nil
	}
	if t == nil || t.AccountID <= 0 {
		return fmt.Errorf("account is required")
	}
	if err := platformpolicy.CheckText(t.Description + " " + t.Goal); err != nil {
		return err
	}
	if _, busy := s.taskFileRestores.Load(t.ID); busy {
		return fmt.Errorf("wait for task files to finish restoring before executing")
	}
	targetID := t.lifecycleSnapshot().SSHTargetID
	if targetID == nil {
		return fmt.Errorf("select a verified VPS before executing this task")
	}
	target, err := s.m.pg.GetSSHTarget(t.AccountID, *targetID)
	if err != nil {
		return fmt.Errorf("VPS is unavailable")
	}
	if !target.AgentLeaseCurrent(time.Now()) {
		return fmt.Errorf("connect a temporary executor with an active lease before executing")
	}
	if !s.agentConnected(t.AccountID, target.ID) {
		return fmt.Errorf("the executor is disconnected; wait for automatic reconnection or check its service on the VPS")
	}
	if target.HostKey == "" || target.Status != "verified" || !preflightComplete(target) {
		return fmt.Errorf("confirm the SSH host key and validate this VPS before executing")
	}
	if len(t.LLMProfileIDs) == 0 {
		return fmt.Errorf("select an LLM profile owned by this account")
	}
	for _, id := range t.LLMProfileIDs {
		owner, err := s.m.pg.ProfileAccountID(id)
		if err != nil || owner != t.AccountID {
			return fmt.Errorf("LLM profile is unavailable")
		}
	}
	return nil
}

func (s *Server) accountAtCapacity(accountID int64, excludeID string) bool {
	if !config.SaaSMode() {
		return false
	}
	for _, task := range s.m.List() {
		if task.AccountID == accountID && task.ID != excludeID && s.occupiesConcurrencySlot(task) {
			return true
		}
	}
	return false
}
