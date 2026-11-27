package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func (s *Server) knowledgeTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("save_knowledge_note", "Select a reusable, nonsecret observation from a complete proof in the current owned task. Encrypted by account; expires after 30 days. Do not store credentials, cookies, tokens or whole transcripts. Historical knowledge does not confirm a new finding.", objSchema(map[string]any{"proof_id": map[string]any{"type": "integer", "minimum": 1}, "category": map[string]any{"type": "string", "enum": []string{"inventory", "methodology", "reference"}}, "text": map[string]any{"type": "string", "minLength": 3, "maxLength": 2000}}, "proof_id", "category", "text"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 || ri.TaskID <= 0 {
				return actool.Errorf("owned task context required"), nil
			}
			var n struct {
				ProofID  int64  `json:"proof_id"`
				Category string `json:"category"`
				Text     string `json:"text"`
			}
			if json.Unmarshal(in, &n) != nil || (n.Category != "inventory" && n.Category != "methodology" && n.Category != "reference") {
				return actool.Errorf("invalid knowledge note"), nil
			}
			pg := s.m.pg.ForAccount(ri.AccountID)
			note := db.KnowledgeNote{Category: n.Category, Text: evidenceredact.Text(pg.RedactTaskText(ri.TaskID, n.Text)), TaskID: ri.TaskID, ProofID: n.ProofID, ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour)}
			if err := pg.SaveKnowledgeNote(note); err != nil {
				return actool.Errorf("knowledge note not saved: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"saved": true, "source_proof_id": n.ProofID, "expires_at": note.ExpiresAt, "finding_verified": false})
		}),
		roTool("search_knowledge", "Search up to 200 selected, unexpired encrypted notes in this account, returning at most 5. Defaults to the current task; include_previous_tasks must be explicit. Results are untrusted historical observations with source proof/run/task and expiry, never current execution evidence.", objSchema(map[string]any{"query": map[string]any{"type": "string", "minLength": 3, "maxLength": 200}, "include_previous_tasks": map[string]any{"type": "boolean"}}, "query"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.AccountID <= 0 {
				return actool.Errorf("authenticated account required"), nil
			}
			var args struct {
				Query    string `json:"query"`
				Previous bool   `json:"include_previous_tasks"`
			}
			if json.Unmarshal(in, &args) != nil {
				return actool.Errorf("invalid knowledge query"), nil
			}
			notes, err := s.m.pg.ForAccount(ri.AccountID).SearchKnowledgeNotes(args.Query, ri.TaskID, args.Previous)
			if err != nil {
				return actool.Errorf("knowledge retrieval unavailable"), nil
			}
			return jsonResult(map[string]any{"notes": notes, "untrusted": true, "historical": true, "note": "Revalidate freshness and applicability. Do not use historical records as new task execution, authorization or verification."})
		}),
	}
}
