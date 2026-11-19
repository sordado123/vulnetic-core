package server

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

const findingReviewerKey = "finding_reviewer"
const findingReviewerPrompt = `Independently review the recorded evidence of the requested finding. First read get_finding_review_context, follow its proof pagination, then use record_finding_evidence_review with exact source IDs, quotes, counterevidence, and confidence_rationale. Do not execute checks or modify findings. Quote presence only checks provenance, not vulnerability validity. Explicitly report missing baselines, alternative explanations and incomplete evidence. This is advisory testing; a human remains responsible for confirmation.`

func normalizeEvidenceQuote(s string) string { return strings.Join(strings.Fields(s), " ") }
func quotePresent(body, quote string) bool {
	return utf8.RuneCountInString(normalizeEvidenceQuote(quote)) >= 8 && strings.Contains(normalizeEvidenceQuote(body), normalizeEvidenceQuote(quote))
}
func boundedEvidenceBody(reader io.Reader, head string) ([]byte, error) {
	encoding := ""
	if response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(head+"\r\n\r\n")), nil); err == nil {
		encoding = strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	}
	var closer io.Closer
	switch encoding {
	case "", "identity":
	case "gzip":
		r, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = r
		closer = r
	case "deflate":
		r, err := zlib.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = r
		closer = r
	default:
		return nil, fmt.Errorf("unsupported evidence encoding")
	}
	if closer != nil {
		defer closer.Close()
	}
	body, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, fmt.Errorf("evidence body exceeds assessment limit")
	}
	return body, nil
}
func redactFindingReview(r *db.FindingEvidenceReview) {
	if r == nil {
		return
	}
	r.Counterevidence = evidenceredact.Text(r.Counterevidence)
	r.ConfidenceRationale = evidenceredact.Text(r.ConfidenceRationale)
	for i := range r.Quotes {
		r.Quotes[i].Quote = evidenceredact.Text(r.Quotes[i].Quote)
	}
}
func (s *Server) assessFindingEvidence(ctx context.Context, accountID, findingID int64, actor string, in *db.FindingEvidenceReview) error {
	if len(in.Quotes) == 0 || len(in.Quotes) > 20 || len(in.Counterevidence) > 16000 || len(in.ConfidenceRationale) < 10 || len(in.ConfidenceRationale) > 16000 {
		return fmt.Errorf("provide 1-20 source quotes, counterevidence and a confidence rationale")
	}
	pg := s.m.pg.ForAccount(accountID)
	f, err := pg.GetFinding(findingID)
	if err != nil || f == nil || f.AccountID != accountID {
		return db.ErrFindingNotFound
	}
	traffic, err := pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return err
	}
	for i := range in.Quotes {
		q := &in.Quotes[i]
		q.Status = "unassessed"
		if len(q.Quote) > 8000 || utf8.RuneCountInString(normalizeEvidenceQuote(q.Quote)) < 8 {
			return fmt.Errorf("quotes must contain 8 or more characters and at most 8000 bytes")
		}
		var body string
		if q.ProofID > 0 && q.TrafficBindingID == 0 {
			p, err := pg.ExecutionProofByID(accountID, q.ProofID)
			if err != nil {
				return fmt.Errorf("execution proof not found")
			}
			if f.TaskID == nil {
				return fmt.Errorf("finding has no task")
			}
			owned := p.TaskID != nil && *p.TaskID == *f.TaskID
			if !owned {
				if err = pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM task_execution_proof_links WHERE account_id=$1 AND task_id=$2 AND proof_id=$3)`, accountID, *f.TaskID, p.ID).Scan(&owned); err != nil {
					return err
				}
			}
			if !owned {
				return fmt.Errorf("proof is not linked to this finding's task")
			}
			if p.Failed || p.Truncated || p.CaptureIncomplete {
				continue
			}
			body = p.Output
		} else if q.TrafficBindingID > 0 && q.ProofID == 0 {
			found := false
			for _, b := range traffic.Bindings {
				if b.ID != q.TrafficBindingID {
					continue
				}
				found = true
				side := q.Side
				if side == "" {
					side = "response"
					q.Side = side
				}
				if side != "request" && side != "response" {
					return fmt.Errorf("invalid evidence side")
				}
				r, _, err := s.evidenceStore(accountID).OpenBody(b.Snapshot, side)
				if err != nil {
					break
				}
				head := b.Snapshot.RespHead
				if side == "request" {
					head = ""
				}
				raw, readErr := boundedEvidenceBody(r, head)
				r.Close()
				if readErr == nil {
					body = string(raw)
				}
				break
			}
			if !found {
				return fmt.Errorf("traffic binding does not belong to finding")
			}
		} else {
			return fmt.Errorf("evidence_source_required: quotes[%d] needs exactly one positive proof_id or traffic_binding_id; call get_finding_review_context(finding_id=%d) first and use an owned source ID returned there", i, findingID)
		}
		if body != "" {
			q.Status = "mismatch"
			if quotePresent(body, q.Quote) {
				q.Status = "matched"
			}
		}
	}
	return pg.SaveFindingEvidenceReview(ctx, accountID, findingID, f.EvidenceVersion, actor, in)
}
func (s *Server) findingEvidenceReviewAPI(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid finding")
		return
	}
	if _, ok = s.findingForAccount(r, id); !ok {
		writeErr(w, 404, "finding not found")
		return
	}
	accountID, userID, _ := accountFromContext(r.Context())
	if r.Method == http.MethodPost {
		var in db.FindingEvidenceReview
		if !decodeConversationRequest(w, r, &in) {
			return
		}
		if err := s.assessFindingEvidence(r.Context(), accountID, id, "human:"+strconv.FormatInt(userID, 10), &in); err != nil {
			writeErr(w, 422, err.Error())
			return
		}
	}
	out, err := s.m.pg.ForAccount(accountID).FindingEvidenceReview(r.Context(), accountID, id)
	if err != nil {
		writeErr(w, 503, "evidence review unavailable")
		return
	}
	redactFindingReview(out)
	writeJSON(w, 200, map[string]any{"review": out, "advisory_only": true})
}
func (s *Server) findingEvidenceTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_finding_review_context", "Read a finding, its bound traffic and masked task proofs for advisory review. No execution or confirmation. Paginate with before.", objSchema(map[string]any{"finding_id": map[string]any{"type": "integer", "minimum": 1}, "before": map[string]any{"type": "integer", "minimum": 0}}, "finding_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64 `json:"finding_id"`
				Before    int64 `json:"before"`
			}
			if json.Unmarshal(in, &a) != nil {
				return actool.Errorf("invalid input"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 {
				return actool.Errorf("account required"), nil
			}
			pg := s.m.pg.ForAccount(ri.AccountID)
			f, err := pg.GetFinding(a.FindingID)
			if err != nil || f == nil || f.AccountID != ri.AccountID {
				return actool.Errorf("finding not found"), nil
			}
			proofs := []db.ExecutionProof{}
			if f.TaskID != nil {
				proofs, err = pg.ExecutionProofsPage(ri.AccountID, f.TaskID, nil, a.Before, 11)
				if err != nil {
					return actool.Errorf("proofs unavailable"), nil
				}
			}
			next := int64(0)
			if len(proofs) > 10 {
				proofs = proofs[:10]
				next = proofs[9].ID
			}
			redactProofPreviews(proofs)
			traffic, err := pg.GetFindingTraffic(ctx, f.ID)
			if err != nil {
				return actool.Errorf("traffic unavailable"), nil
			}
			review, err := pg.FindingEvidenceReview(ctx, ri.AccountID, f.ID)
			if err != nil {
				return actool.Errorf("review unavailable"), nil
			}
			redactFindingReview(review)
			return jsonResult(map[string]any{"finding_id": f.ID, "task_id": f.TaskID, "summary": trunc(evidenceredact.Text(f.Summary), 8000), "evidence": trunc(evidenceredact.Text(f.Evidence), 16000), "evidence_version": f.EvidenceVersion, "verification_state": f.VerificationState, "proofs": proofs, "next_cursor": next, "traffic": trafficSummary(traffic), "review": review, "advisory_only": true})
		}),
		wrTool("record_finding_evidence_review", "Record advisory counterevidence and confidence rationale; deterministically compare quotes with the exact owned proof or finding-bound traffic. Never verifies or confirms a finding.", objSchema(map[string]any{"finding_id": map[string]any{"type": "integer", "minimum": 1}, "counterevidence": map[string]any{"type": "string"}, "confidence_rationale": map[string]any{"type": "string", "minLength": 10, "maxLength": 16000}, "quotes": map[string]any{"type": "array", "minItems": 1, "maxItems": 20, "items": objSchema(map[string]any{"proof_id": map[string]any{"type": "integer", "minimum": 1}, "traffic_binding_id": map[string]any{"type": "integer", "minimum": 1}, "side": map[string]any{"type": "string", "enum": []string{"request", "response"}}, "quote": map[string]any{"type": "string", "minLength": 8, "maxLength": 8000}}, "quote")}}, "finding_id", "confidence_rationale", "quotes"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64 `json:"finding_id"`
				db.FindingEvidenceReview
			}
			if json.Unmarshal(in, &a) != nil {
				return actool.Errorf("invalid review"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 {
				return actool.Errorf("account required"), nil
			}
			actor := "agent:worker"
			if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
				c, err := s.m.pg.ForAccount(ri.AccountID).GetConversation(convID)
				if err != nil || c == nil {
					return actool.Errorf("conversation unavailable"), nil
				}
				actor = "agent:" + c.AgentKey
			}
			if err := s.assessFindingEvidence(ctx, ri.AccountID, a.FindingID, actor, &a.FindingEvidenceReview); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			redactFindingReview(&a.FindingEvidenceReview)
			return jsonResult(map[string]any{"review": a.FindingEvidenceReview, "advisory_only": true, "notice": "A matched quote establishes text provenance only. Human execution-evidence review is still required."})
		}),
	}
}
func (s *Server) startFindingEvidenceReview(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid finding")
		return
	}
	f, ok := s.findingForAccount(r, id)
	if !ok || f.TaskID == nil {
		writeErr(w, 404, "finding with task not found")
		return
	}
	accountID, userID, _ := accountFromContext(r.Context())
	pg := s.m.pg.ForAccount(accountID)
	a, err := pg.GetAgentByKey(findingReviewerKey)
	if err != nil || a == nil || !a.Enabled {
		writeErr(w, 409, "enable the evidence reviewer agent first")
		return
	}
	tx, err := pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 503, "unable to create review")
		return
	}
	defer tx.Rollback()
	scoped := *pg
	scoped.Querier = tx
	c, err := scoped.CreateConversation(accountID, findingReviewerKey, fmt.Sprintf("Evidence review #%d", id), nil, userID)
	if err == nil {
		err = scoped.BindTriggeredConversation(accountID, c.ID, *f.TaskID)
	}
	if err != nil {
		writeErr(w, 503, "unable to link review to original task")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 503, "unable to save review conversation")
		return
	}
	writeJSON(w, 200, map[string]any{"conversation_id": c.ID, "message": fmt.Sprintf("Review finding #%d independently. Use get_finding_review_context, then record_finding_evidence_review. Keep the human verification unchanged.", id), "advisory_only": true})
}
