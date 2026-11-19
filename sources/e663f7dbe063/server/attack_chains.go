package server

import (
	"net/http"
	"strconv"
)

// taskAttackChains serves the attack chains the agent declared for a task (#24):
// the ordered findings and the narrative of how they escalate. Account-scoped via
// taskForAccount, so one tenant never reads another's chains.
func (s *Server) taskAttackChains(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, 500, "task id is not numeric")
		return
	}
	accountID := mustRequestAccount(r)
	chains, err := s.m.pg.ForAccount(accountID).AttackChains(r.Context(), accountID, taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"chains": chains})
}
