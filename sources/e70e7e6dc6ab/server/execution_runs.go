package server

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	"github.com/sordado123/vulnetic/internal/runstate"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var activeExecutionRuns sync.Map

func (s *Server) startExecution(ctx context.Context, ri agent.RunInfo) (context.Context, error) {
	if runstate.From(ctx) != nil {
		return ctx, nil
	}
	if ri.AccountID <= 0 {
		return ctx, fmt.Errorf("execution account required")
	}
	if ri.TaskID > 0 {
		if task, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10)); ok && task.AccountID == ri.AccountID && task.lifecycleSnapshot().Status == "created" && !task.lifecycleSnapshot().Paused && !task.lifecycleSnapshot().Queued {
			if _, err := s.m.SetTaskStatusGuarded(task.ID, "running"); err != nil {
				return ctx, err
			}
		}
	}
	convID := intercept.ConvIDFromContext(ctx)
	snap := runstate.Snapshot{ID: uuid.NewString(), ConversationID: convID, TaskID: ri.TaskID, ExecutorID: ri.ExecutorID, IntentID: ri.IntentID, Lane: ri.SessionID, DurationLimitSeconds: runstate.DurationFrom(ctx)}
	activeExecutionRuns.Store(snap.ID, true)
	state, err := runstate.New(snap, func(value runstate.Snapshot) error {
		err := s.m.pg.SaveExecutionRun(ri.AccountID, value)
		if value.FinishedAt != nil {
			activeExecutionRuns.Delete(value.ID)
		}
		return err
	})
	if err != nil {
		activeExecutionRuns.Delete(snap.ID)
		return ctx, err
	}
	return runstate.Bind(ctx, state), nil
}
func executionRunViews(items []runstate.Snapshot) []runstate.Snapshot {
	for i := range items {
		r := &items[i]
		if r.Status != "running" {
			continue
		}
		if _, ok := activeExecutionRuns.Load(r.ID); !ok {
			r.Status = "interrupted"
			r.Phase = "finished"
			r.Code = "service_restart"
			r.Message = "The service stopped before this execution recorded a final state."
			r.Recovery = "Review the last returned results before continuing. No commands were replayed and executor expiry was not renewed."
			r.Checkpoint = fmt.Sprintf("%d tool calls returned; %d have an unknown outcome. Evidence is preserved under run %s.", r.CompletedTools, r.PendingTools, r.ID)
		}
	}
	return items
}
func (s *Server) conversationRuns(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	items, err := pg.ExecutionRuns(c.AccountID, 0, c.ID)
	if err != nil {
		writeErr(w, 503, "Execution status is unavailable; retry shortly")
		return
	}
	unreturned, err := legacyUnreturnedTools(pg, c.AccountID, 0, c.ID)
	if err != nil {
		writeErr(w, 503, "Execution history status is unavailable")
		return
	}
	var input, output int64
	if err := pg.QueryRow(`SELECT coalesce(sum(input_tokens),0),coalesce(sum(output_tokens),0) FROM llm_usage WHERE account_id=$1 AND conversation_id=$2`, c.AccountID, c.ID).Scan(&input, &output); err != nil {
		writeErr(w, 503, "Execution usage is unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"interrupted_tool_calls": unreturned, "attributed_tokens": input + output, "items": executionRunViews(items), "token_limit": runstate.TokenLimit(), "legacy_attribution": "Older calls without an execution or conversation ID remain in the account total.", "source_task_id": c.SourceTaskID})
}
func (s *Server) taskRuns(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		writeErr(w, 404, "task not found")
		return
	}
	pg := s.m.pg.ForAccount(t.AccountID)
	items, err := pg.ExecutionRuns(t.AccountID, id, 0)
	if err != nil {
		writeErr(w, 503, "Execution status is unavailable; retry shortly")
		return
	}
	var open, running int
	err = pg.QueryRow(`SELECT count(*) FILTER(WHERE state='open'),count(*) FILTER(WHERE state='running') FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'`, t.Store.ID()).Scan(&open, &running)
	if err != nil {
		writeErr(w, 503, "Task progress is unavailable")
		return
	}
	unreturned, err := legacyUnreturnedTools(pg, t.AccountID, id, 0)
	if err != nil {
		writeErr(w, 503, "Execution history status is unavailable")
		return
	}
	var candidates, verified, reportPending int
	if err := pg.QueryRow(`SELECT count(*) FILTER(WHERE NOT EXISTS(SELECT 1 FROM finding_verifications v WHERE v.account_id=f.account_id AND v.finding_id=f.id AND v.evidence_version=f.evidence_version AND v.source_evidence=f.evidence AND v.source_summary=f.summary AND EXISTS(SELECT 1 FROM finding_verification_proofs b WHERE b.verification_id=v.id))), count(*) FILTER(WHERE EXISTS(SELECT 1 FROM finding_verifications v WHERE v.account_id=f.account_id AND v.finding_id=f.id AND v.evidence_version=f.evidence_version AND v.source_evidence=f.evidence AND v.source_summary=f.summary AND EXISTS(SELECT 1 FROM finding_verification_proofs b WHERE b.verification_id=v.id))), count(*) FILTER(WHERE coalesce(f.report,'')='' OR f.report_evidence_version<>f.evidence_version) FROM findings f WHERE f.account_id=$1 AND f.task_id=$2`, t.AccountID, id).Scan(&candidates, &verified, &reportPending); err != nil {
		writeErr(w, 503, "Finding workflow status is unavailable")
		return
	}
	var pausedIntents, doneIntents, goalsOpen, goalsMet int
	if err = pg.QueryRow("SELECT count(*) FILTER(WHERE kind='intent' AND state='paused'),count(*) FILTER(WHERE kind='intent' AND state='done'),count(*) FILTER(WHERE kind='goal' AND state='open'),count(*) FILTER(WHERE kind='goal' AND state='met') FROM exploration_nodes WHERE exploration_id=$1", t.Store.ID()).Scan(&pausedIntents, &doneIntents, &goalsOpen, &goalsMet); err != nil {
		writeErr(w, 503, "Delivery progress unavailable")
		return
	}
	workflow := fmt.Sprintf("Findings: %d awaiting evidence review, %d verified. Reports: %d missing or awaiting update. Execution completion does not confirm findings.", candidates, verified, reportPending)
	summary := fmt.Sprintf("Execution: %s. Work: %d completed, %d running, %d queued, %d paused/waiting for input. Goals: %d met, %d remaining. ", s.resolvedTaskStatus(t), doneIntents, running, open, pausedIntents, goalsMet, goalsOpen) + workflow
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		summary += " " + fmt.Sprintf("Execution is %s. %d open and %d running intents remain in its history; they are not resumed automatically. Paused is an execution barrier, not an additional outcome.", t.lifecycleSnapshot().Status, open, running)
	}
	writeJSON(w, 200, map[string]any{"items": executionRunViews(items), "token_limit": runstate.TokenLimit(), "task_summary": summary, "delivery": map[string]int{"work_done": doneIntents, "work_running": running, "work_queued": open, "work_paused": pausedIntents, "goals_met": goalsMet, "goals_open": goalsOpen}, "finding_workflow": map[string]int{"candidates": candidates, "verified": verified, "reports_pending": reportPending}, "interrupted_tool_calls": unreturned, "open_intents": open, "running_intents": running, "server_time": time.Now().UTC()})
}
func legacyUnreturnedTools(pg *db.DB, accountID, taskID, convID int64) (int, error) {
	var n int
	if convID > 0 {
		err := pg.QueryRow(`SELECT count(*) FROM conversation_activities a JOIN conversations owner ON owner.id=a.conversation_id WHERE owner.account_id=$2 AND a.conversation_id=$1 AND a.kind='tool_use' AND coalesce(a.tool_use_id,'')<>'' AND NOT EXISTS(SELECT 1 FROM conversation_activities b WHERE b.conversation_id=a.conversation_id AND b.kind='tool_result' AND b.tool_use_id=a.tool_use_id) AND EXISTS(SELECT 1 FROM conversation_activities c WHERE c.conversation_id=a.conversation_id AND c.kind='result' AND c.id>a.id)`, convID, accountID).Scan(&n)
		return n, err
	}
	err := pg.QueryRow(`SELECT count(*) FROM activity a JOIN tasks t ON t.exploration_id=a.exploration_id WHERE t.id=$1 AND t.account_id=$2 AND a.kind='tool_use' AND coalesce(a.tool_use_id,'')<>'' AND NOT EXISTS(SELECT 1 FROM activity b WHERE b.exploration_id=a.exploration_id AND b.kind='tool_result' AND b.tool_use_id=a.tool_use_id) AND (t.status IN ('done','timeout','failed') OR EXISTS(SELECT 1 FROM activity c WHERE c.exploration_id=a.exploration_id AND c.kind='result' AND c.id>a.id AND c.node_id IS NOT DISTINCT FROM a.node_id AND c.worker IS NOT DISTINCT FROM a.worker))`, taskID, accountID).Scan(&n)
	return n, err
}

func runSummaryActivity(snap runstate.Snapshot) db.Activity {
	return db.Activity{Kind: "checkpoint", Summary: snap.Message, Detail: snap.Checkpoint + "\n" + snap.Recovery}
}
