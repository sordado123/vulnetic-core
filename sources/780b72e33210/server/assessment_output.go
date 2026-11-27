package server

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/assessment"
	"github.com/sordado123/vulnetic/intercept"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func (s *Server) toolParseAssessmentOutput() actool.CoreTool {
	return wrTool("parse_assessment_output", "Normalize Nmap XML, httpx/Katana/Nuclei JSONL or ffuf JSON from an owned execution proof. Does not run a scanner or confirm findings. Preserves source proof, task, conversation and run. Use findings as candidates only.", objSchema(map[string]any{"format": map[string]any{"type": "string", "enum": []string{"nmap", "httpx", "katana", "ffuf", "nuclei"}}, "proof_id": map[string]any{"type": "integer", "minimum": 1}}, "format", "proof_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		ri := agent.RunInfoFrom(ctx)
		if ri.AccountID <= 0 {
			return actool.Errorf("authenticated account required"), nil
		}
		var args struct {
			Format  string `json:"format"`
			ProofID int64  `json:"proof_id"`
		}
		if json.Unmarshal(in, &args) != nil || args.ProofID <= 0 {
			return actool.Errorf("invalid scanner proof"), nil
		}
		proof, err := s.m.pg.ForAccount(ri.AccountID).ExecutionProofByID(ri.AccountID, args.ProofID)
		if err != nil || proof == nil {
			return actool.Errorf("execution proof not found"), nil
		}
		// Scope cannot be widened by supplying another task's proof id.
		if ri.TaskID > 0 {
			if proof.TaskID == nil || *proof.TaskID != ri.TaskID {
				return actool.Errorf("use a proof from the current task; preserve explicit cross-task links separately"), nil
			}
		} else if id := intercept.ConvIDFromContext(ctx); id <= 0 || proof.ConversationID == nil || *proof.ConversationID != id {
			return actool.Errorf("use a proof from this conversation"), nil
		}
		if proof.CaptureIncomplete || (proof.Truncated && proof.FullArtifactID == "") {
			return actool.Errorf("scanner capture is incomplete; capture a complete bounded output first"), nil
		}
		raw := strings.TrimSpace(proof.Output)
		if proof.FullArtifactID != "" {
			artifact, err := s.loadProofArtifact(proof)
			if err != nil {
				return actool.Errorf("scanner artifact could not be verified"), nil
			}
			raw = strings.TrimSpace(artifact.Output)
		}
		if proof.Tool == "run_network_inventory" && args.Format == "nmap" {
			var envelope struct {
				XML string `json:"raw_xml"`
			}
			if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.XML == "" {
				return actool.Errorf("network inventory proof has no complete XML"), nil
			}
			raw = envelope.XML
		}
		rows, err := assessment.Parse(args.Format, []byte(raw))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(map[string]any{"observations": rows, "source_proof_id": proof.ID, "source_task_id": proof.TaskID, "source_conversation_id": proof.ConversationID, "source_run_id": proof.RunID, "source_failed": proof.Failed, "untrusted": true, "verified": false, "note": "Scanner observations and version claims are candidates. Reproduce against the approved scope, preserve controls and original evidence, then submit for human review."})
	})
}
