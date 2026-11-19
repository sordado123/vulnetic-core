package server

import (
	"net/http"

	"github.com/sordado123/vulnetic/db"
)

// accountReadiness reports how far an account is along the path to its first
// finding (onboarding): whether an LLM profile has a key, whether a verified
// execution agent exists, how many tasks were created, and how many findings
// landed. The frontend turns this into a guided checklist. Account-scoped.
func (s *Server) accountReadiness(w http.ResponseWriter, r *http.Request) {
	accountID := mustRequestAccount(r)

	profile, err := s.m.pg.ActiveProfileForAccount(accountID)
	if err != nil {
		writeErr(w, 503, "account status unavailable")
		return
	}
	targets, err := s.m.pg.ListSSHTargets(accountID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	verified := 0
	for _, t := range targets {
		if t.Status == db.SSHTargetVerified {
			verified++
		}
	}
	tasks := 0
	for _, t := range s.m.List() {
		if t.AccountID == accountID {
			tasks++
		}
	}
	out := map[string]any{
		"llm_configured":     profile != nil && (profile.APIKey != "" || profile.Format == "ollama"),
		"executors":          len(targets),
		"executors_verified": verified,
		"tasks":              tasks,
		"findings":           0,
	}
	if st, err := s.m.pg.ForAccount(accountID).FindingStats(); err == nil {
		out["findings"] = st.Total
	}
	writeJSON(w, 200, out)
}
