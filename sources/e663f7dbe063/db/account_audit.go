package db

import "time"

type AuditEvent struct {
	ID        int64     `json:"id"`
	UserID    *int64    `json:"user_id,omitempty"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Status    int       `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) RecordAudit(accountID, userID int64, action, resource string, status int) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	_, err := d.Exec(`INSERT INTO account_audit(account_id,user_id,action,resource,status) VALUES($1,$2,$3,$4,$5)`, accountID, nullIfZero(userID), action, resource, status)
	return err
}
func (d *DB) ListAudit(accountID int64) ([]AuditEvent, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	rows, err := d.Query(`SELECT id,user_id,action,resource,status,created_at FROM account_audit WHERE account_id=$1 ORDER BY id DESC LIMIT 200`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var event AuditEvent
		if err = rows.Scan(&event.ID, &event.UserID, &event.Action, &event.Resource, &event.Status, &event.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}
