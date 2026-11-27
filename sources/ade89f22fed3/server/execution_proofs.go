package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
)

func (s *Server) wireExecutionProofs() {
	agent.RedactToolText = func(ctx context.Context, text string) string {
		ri := agent.RunInfoFrom(ctx)
		return s.operatorInputs.Redact(ri.AccountID, ri.TaskID, intercept.ConvIDFromContext(ctx), text)
	}
	agent.StartExecution = s.startExecution
	agent.RecordExecutionProofReference = func(ctx context.Context, run agent.RunInfo, runID, tool string, input json.RawMessage, output string, failed bool) (int64, error) {
		if !config.SaaSMode() || strings.TrimSpace(output) == "" {
			return 0, nil
		}
		if run.AccountID <= 0 || run.Executor == nil {
			return 0, nil
		}
		eligible := tool == "Bash" || tool == "remote_http_request" || tool == "run_network_inventory" || tool == "read_web_page" || tool == "browser_session" || strings.HasPrefix(tool, "mcp__")
		if !eligible {
			row, err := s.m.pg.ForAccount(run.AccountID).GetTool(tool)
			if err != nil {
				return 0, err
			}
			eligible = row != nil && !row.System && (row.Kind == "command" || row.Kind == "script" || row.Kind == "http")
		}
		if !eligible {
			return 0, nil
		}
		proof := db.ExecutionProof{Failed: failed, CaptureIncomplete: strings.Contains(output, "characters truncated]") || strings.Contains(output, "<persisted-output>") || ((tool == "remote_http_request" || tool == "read_web_page") && strings.Contains(output, `"truncated":true`)) || (tool == "browser_session" && strings.Contains(output, `"text_truncated":true`)), AccountID: run.AccountID, UserID: run.UserID, RunID: runID, Tool: tool, Input: input, Output: output}
		if run.ExecutorID > 0 {
			executorID := run.ExecutorID
			proof.ExecutorID = &executorID
		}
		if run.TaskID > 0 {
			proof.TaskID = &run.TaskID
		}
		if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
			proof.ConversationID = &convID
		}
		id, err := s.persistProof(ctx, proof)
		if err != nil {
			s.evidenceFailures.Add(1)
		}
		return id, err
	}
	agent.RecordExecutionProof = func(ctx context.Context, ri agent.RunInfo, runID, name string, input json.RawMessage, output string, failed bool) error {
		_, err := agent.RecordExecutionProofReference(ctx, ri, runID, name, input, output, failed)
		return err
	}
}

func (s *Server) taskExecutionProofs(w http.ResponseWriter, r *http.Request) {
	task, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := parseTaskID(task.ID)
	if err != nil {
		writeErr(w, 404, "task not found")
		return
	}
	proofs, err := s.m.pg.ExecutionProofsPage(task.AccountID, &id, nil, proofCursor(r), 26)
	if err != nil {
		writeErr(w, 503, "Execution evidence unavailable")
		return
	}
	next := int64(0)
	if len(proofs) > 25 {
		proofs = proofs[:25]
		next = proofs[24].ID
	}
	redactProofPreviews(proofs)
	writeJSON(w, 200, map[string]any{"proofs": proofs, "next_cursor": next, "traffic_capture": "unavailable"})
}
func (s *Server) conversationExecutionProofs(w http.ResponseWriter, r *http.Request) {
	_, conv, ok := s.convByID(w, r)
	if !ok {
		return
	}
	proofs, err := s.m.pg.ExecutionProofsPage(conv.AccountID, nil, &conv.ID, proofCursor(r), 26)
	if err != nil {
		writeErr(w, 503, "Execution evidence unavailable")
		return
	}
	next := int64(0)
	if len(proofs) > 25 {
		proofs = proofs[:25]
		next = proofs[24].ID
	}
	redactProofPreviews(proofs)
	writeJSON(w, 200, map[string]any{"proofs": proofs, "next_cursor": next})
}

func redactProofPreviews(proofs []db.ExecutionProof) {
	for i := range proofs {
		proofs[i].Input = evidenceredact.JSON(proofs[i].Input)
		proofs[i].Output = evidenceredact.Text(proofs[i].Output)
		// The response hash describes its remasked preview, not the stored original.
		digest := sha256.Sum256([]byte(proofs[i].Output))
		proofs[i].PreviewDigest = hex.EncodeToString(digest[:])
	}
}
func (s *Server) verifyFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid finding id")
		return
	}
	if _, ok = s.findingForAccount(r, id); !ok {
		writeErr(w, 404, "finding not found")
		return
	}
	var req struct {
		ProofIDs []int64 `json:"proof_ids"`
		Steps    string  `json:"steps"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	accountID, userID, ok := accountFromContext(r.Context())
	if !ok {
		writeErr(w, 401, "authentication required")
		return
	}
	if err := s.validateProofArtifacts(accountID, req.ProofIDs); err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	if err := s.m.pg.ForAccount(accountID).VerifyFinding(r.Context(), accountID, userID, id, req.ProofIDs, req.Steps); err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"verification_state": "verified"})
}

// findingVerificationPlaybook returns the recorded reproduction playbook for a
// finding: the reviewer's steps, the confirmed claim, and the linked execution
// proofs — the "how to reproduce" read view. 200 with {exists:false} when the
// finding was never verified.
func (s *Server) findingVerificationPlaybook(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid finding id")
		return
	}
	if _, ok = s.findingForAccount(r, id); !ok {
		writeErr(w, 404, "finding not found")
		return
	}
	accountID, _, ok := accountFromContext(r.Context())
	if !ok {
		writeErr(w, 401, "authentication required")
		return
	}
	pb, err := s.m.pg.ForAccount(accountID).FindingVerificationPlaybook(r.Context(), accountID, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if pb == nil {
		writeJSON(w, 200, map[string]any{"exists": false})
		return
	}
	writeJSON(w, 200, map[string]any{"exists": true, "playbook": pb})
}

func proofCursor(r *http.Request) int64 {
	v, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
