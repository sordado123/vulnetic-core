package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type KnowledgeNote struct {
	Category  string    `json:"category"`
	Text      string    `json:"text"`
	TaskID    int64     `json:"source_task_id"`
	ProofID   int64     `json:"source_proof_id"`
	RunID     string    `json:"source_run_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (d *DB) SaveKnowledgeNote(n KnowledgeNote) error {
	if !d.hasAccount || d.accountID <= 0 {
		return errors.New("authenticated account required")
	}
	if n.TaskID <= 0 || n.ProofID <= 0 || len(n.Text) < 3 || len(n.Text) > 2000 || n.ExpiresAt.IsZero() {
		return errors.New("invalid knowledge note")
	}
	// Source eligibility is checked again here, not trusted from a caller's note.
	p, err := d.ExecutionProofByID(d.accountID, n.ProofID)
	if err != nil || p == nil || p.TaskID == nil || *p.TaskID != n.TaskID || p.Failed || p.CaptureIncomplete {
		return errors.New("complete owned task proof required")
	}
	n.RunID = p.RunID
	n.CreatedAt = time.Now().UTC()
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if !d.encryptSecrets {
		return errors.New("knowledge vault unavailable")
	}
	sealed, err := d.sealJSON(d.accountID, raw)
	if err != nil {
		return err
	}
	return d.SetSetting(fmt.Sprintf("knowledge.note.v1.%d.%d", n.TaskID, n.ProofID), string(sealed))
}

// Bounded retrieval is intentional: selected notes, not raw transcripts or embeddings of secrets.
func (d *DB) SearchKnowledgeNotes(query string, taskID int64, includePrevious bool) ([]KnowledgeNote, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return nil, errors.New("authenticated account required")
	}
	query = strings.TrimSpace(query)
	if len(query) < 3 || len(query) > 200 {
		return nil, errors.New("query must contain 3–200 bytes")
	}
	rows, err := d.Query(`SELECT value FROM account_settings WHERE account_id=$1 AND key LIKE 'knowledge.note.v1.%' ORDER BY updated_at DESC LIMIT 200`, d.accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KnowledgeNote{}
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		raw, err := d.openJSON(d.accountID, json.RawMessage(value))
		if err != nil {
			return nil, err
		}
		var n KnowledgeNote
		if json.Unmarshal(raw, &n) != nil {
			return nil, errors.New("knowledge note unavailable")
		}
		if time.Now().After(n.ExpiresAt) || (!includePrevious && n.TaskID != taskID) {
			continue
		}
		matches := true
		text := strings.ToLower(n.Text)
		for _, word := range strings.Fields(strings.ToLower(query)) {
			if !strings.Contains(text, word) {
				matches = false
				break
			}
		}
		if matches && len(out) < 5 {
			out = append(out, n)
		}
	}
	return out, rows.Err()
}
