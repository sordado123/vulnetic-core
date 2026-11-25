package db

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/sordado123/vulnetic/internal/evidenceredact"
	"github.com/sordado123/vulnetic/internal/operatorinput"
)

type OperatorRequest struct {
	TaskID         int64              `json:"task_id"`
	IntentID       int64              `json:"intent_id"`
	ConversationID int64              `json:"conversation_id"`
	Seq            int64              `json:"seq"`
	Title          string             `json:"title"`
	Question       string             `json:"question"`
	CreatedAt      time.Time          `json:"created_at"`
	Input          operatorinput.Spec `json:"input"`
}

// A reply clears only its own request; a paused task retains unanswered requests after restart.
func (d *DB) OperatorRequests() ([]OperatorRequest, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return nil, sql.ErrNoRows
	}
	rows, err := d.Query(`SELECT * FROM (
SELECT t.id AS task_id,n.id AS intent_id,0::bigint AS conversation_id,a.id AS seq,COALESCE(NULLIF(t.name,''),'Task #'||t.id::text) AS title,a.summary AS question,a.created_at,COALESCE(a.detail,'') AS request_data
FROM tasks t JOIN exploration_nodes n ON n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state='paused'
JOIN LATERAL (SELECT id,summary,detail,created_at FROM activity WHERE exploration_id=t.exploration_id AND node_id=n.id AND kind='user' ORDER BY id DESC LIMIT 1) a ON true
WHERE t.account_id=$1 AND t.deleted_at IS NULL AND t.status NOT IN ('done','failed','timeout') AND a.summary LIKE 'OPERATOR INPUT REQUESTED:%'
UNION ALL
SELECT 0::bigint,0::bigint,c.id,a.id,COALESCE(NULLIF(c.title,''),'Chat #'||c.id::text),a.summary,a.created_at,COALESCE(a.detail,'')
FROM conversations c JOIN LATERAL (SELECT id,kind,summary,detail,created_at FROM conversation_activities WHERE conversation_id=c.id AND kind IN ('user','operator_request') ORDER BY id DESC LIMIT 1) a ON true
WHERE c.account_id=$1 AND a.kind='operator_request'
) requests ORDER BY created_at DESC LIMIT 100`, d.accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OperatorRequest{}
	for rows.Next() {
		var item OperatorRequest
		var raw string
		if err = rows.Scan(&item.TaskID, &item.IntentID, &item.ConversationID, &item.Seq, &item.Title, &item.Question, &item.CreatedAt, &raw); err != nil {
			return nil, err
		}
		item.Question = evidenceredact.Text(item.Question)
		var payload struct {
			Input operatorinput.Spec `json:"input_request"`
		}
		_ = json.Unmarshal([]byte(raw), &payload)
		item.Input = payload.Input
		if item.Input.Type == "" {
			item.Input.Type = "text"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
