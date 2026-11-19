package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/sordado123/vulnetic/internal/runstate"
)

func (d *DB) SaveExecutionRun(accountID int64, s runstate.Snapshot) error {
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) {
		return sql.ErrNoRows
	}
	d = d.ForAccount(accountID)
	if s.ID == "" {
		return errors.New("execution id required")
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	res, err := d.Exec(`INSERT INTO execution_runs(id,account_id,task_id,conversation_id,payload) SELECT $1,$2,NULLIF($3,0),NULLIF($4,0),$5 WHERE ($3::bigint=0 OR EXISTS(SELECT 1 FROM tasks t WHERE t.id=$3 AND t.account_id=$2 AND t.deleted_at IS NULL)) AND ($4::bigint=0 OR EXISTS(SELECT 1 FROM conversations c WHERE c.id=$4 AND c.account_id=$2)) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=now() WHERE execution_runs.account_id=excluded.account_id`, s.ID, accountID, s.TaskID, s.ConversationID, string(payload))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return sql.ErrNoRows
	}
	return err
}
func (d *DB) ExecutionRuns(accountID, taskID, convID int64) ([]runstate.Snapshot, error) {
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) {
		return nil, sql.ErrNoRows
	}
	d = d.ForAccount(accountID)
	rows, err := d.Query(`SELECT payload FROM execution_runs WHERE account_id=$1 AND (($2::bigint>0 AND task_id=$2) OR ($3::bigint>0 AND conversation_id=$3)) ORDER BY updated_at DESC LIMIT 50`, accountID, taskID, convID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []runstate.Snapshot{}
	for rows.Next() {
		var b []byte
		var s runstate.Snapshot
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
