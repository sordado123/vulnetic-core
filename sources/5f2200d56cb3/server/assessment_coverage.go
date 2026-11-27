package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/assessment"
	"github.com/sordado123/vulnetic/db"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func readAssessmentCoverage(pg *db.DB, taskID int64) ([]assessment.Coverage, error) {
	if taskID <= 0 || pg.ScopedAccountID() <= 0 {
		return []assessment.Coverage{}, nil
	}
	return pg.AssessmentCoverage(taskID)
}

func (s *Server) taskAssessment(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "Task not found")
		return
	}
	registryID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || registryID <= 0 {
		writeErr(w, 404, "Task not found")
		return
	}
	rows, err := readAssessmentCoverage(s.m.pg.ForAccount(t.AccountID), registryID)
	if err != nil {
		writeErr(w, 503, "Assessment coverage unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"version": 1, "methodologies": assessment.Methodologies, "coverage": rows, "human_review_required": true})
}

func (s *Server) assessmentCoverageTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_assessment_plan", "Read versioned web/API/network/directory assessment checklists and recorded coverage for the current owned task. Untested and blocked checks are gaps, not negative findings. This grants no execution permissions.", objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 || ri.TaskID <= 0 {
				return actool.Errorf("owned task context required"), nil
			}
			pg := s.m.pg.ForAccount(ri.AccountID)
			if task, err := pg.GetTask(ri.TaskID); err != nil || task == nil {
				return actool.Errorf("task not found"), nil
			}
			rows, err := readAssessmentCoverage(pg, ri.TaskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"version": 1, "methodologies": assessment.Methodologies, "coverage": rows, "note": "Choose checks applicable to the approved scope. Do not infer coverage or authorization from a checklist."})
		}),
		wrTool("record_assessment_check", "Record one methodology check for the current owned task. Tested/candidate states require complete successful execution proofs from this task. Records coverage only; never confirms a finding. Preserve blockers, negative controls and reproduction limits in the note without secrets.", objSchema(map[string]any{
			"profile": map[string]any{"type": "string", "enum": []string{"web", "api", "network", "ad"}}, "check": map[string]any{"type": "string"},
			"state": map[string]any{"type": "string", "enum": []string{"tested", "not_tested", "blocked", "inconclusive", "candidate"}}, "note": map[string]any{"type": "string", "maxLength": 1600},
			"proof_ids": map[string]any{"type": "array", "maxItems": 8, "items": map[string]any{"type": "integer", "minimum": 1}},
		}, "profile", "check", "state", "note"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 || ri.TaskID <= 0 {
				return actool.Errorf("owned task context required"), nil
			}
			var c assessment.Coverage
			if json.Unmarshal(in, &c) != nil {
				return actool.Errorf("invalid assessment check"), nil
			}
			pg := s.m.pg.ForAccount(ri.AccountID)
			c, err := pg.RecordAssessmentCheck(ctx, ri.TaskID, c)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"coverage": c, "finding_verified": false})
		}),
	}
}
