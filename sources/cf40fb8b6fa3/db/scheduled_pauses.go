package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ScheduledPause is one chat-created, one-shot "pause at this absolute time"
// action (scheduled_task_actions, action='pause'). Unlike agent_triggers, the
// scheduler fires this directly — no LLM run in between — so it actually
// happens even if no agent is around to interpret a triggered message.
// TaskID empty means "every task running at fire time", not one specific task.
type ScheduledPause struct {
	AccountID int64      `json:"-"`
	ID        int64      `json:"id"`
	TaskID    string     `json:"task_id"`
	RunAt     time.Time  `json:"run_at"`
	FiredAt   *time.Time `json:"fired_at,omitempty"`
	Cancelled bool       `json:"cancelled"`
	Note      string     `json:"note"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

const scheduledPauseCols = `id, account_id, task_id, run_at, fired_at, cancelled, note, created_by, created_at`

func scanScheduledPause(sc interface{ Scan(...any) error }) (*ScheduledPause, error) {
	var p ScheduledPause
	var firedAt sql.NullTime
	if err := sc.Scan(&p.ID, &p.AccountID, &p.TaskID, &p.RunAt, &firedAt, &p.Cancelled, &p.Note, &p.CreatedBy, &p.CreatedAt); err != nil {
		return nil, err
	}
	if firedAt.Valid {
		p.FiredAt = &firedAt.Time
	}
	return &p, nil
}

// CreateScheduledPause schedules a one-shot pause. taskID="" targets every
// task still running at fire time, not just the ones running now.
func (d *DB) CreateScheduledPause(accountID int64, taskID string, runAt time.Time, note, createdBy string) (*ScheduledPause, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if accountID <= 0 {
		return nil, fmt.Errorf("account is required")
	}
	if taskID != "" {
		var owned bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE id::text=$1 AND account_id=$2 AND deleted_at IS NULL AND archived_at IS NULL)`, taskID, accountID).Scan(&owned); err != nil {
			return nil, err
		}
		if !owned {
			return nil, fmt.Errorf("task not found")
		}
	}
	row := d.QueryRow(`
INSERT INTO scheduled_task_actions(task_id, action, run_at, note, created_by, account_id)
VALUES ($1, 'pause', $2, $3, $4,$5) RETURNING `+scheduledPauseCols,
		taskID, runAt, note, createdBy, accountID)
	return scanScheduledPause(row)
}

// ListDueScheduledPauses returns unfired, uncancelled pauses whose run_at has
// passed — the scheduler's poll query. Ordered so the oldest fires first.
func (d *DB) ListDueScheduledPauses(now time.Time) ([]*ScheduledPause, error) {
	rows, err := d.Query(`
SELECT `+scheduledPauseCols+`
FROM scheduled_task_actions
WHERE action = 'pause' AND account_id IS NOT NULL AND fired_at IS NULL AND NOT cancelled AND run_at <= $1
ORDER BY run_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScheduledPause
	for rows.Next() {
		p, err := scanScheduledPause(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkScheduledPauseFired records that a scheduled pause has run, so the
// scheduler's next poll does not fire it again.
func (d *DB) MarkScheduledPauseFired(id int64) error {
	_, err := d.Exec(`UPDATE scheduled_task_actions SET fired_at = now() WHERE id = $1`, id)
	return err
}

// CancelScheduledPause marks a pending scheduled pause as cancelled. A no-op
// (not an error) if it already fired or was already cancelled.
func (d *DB) CancelScheduledPause(accountID, id int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	_, err := d.Exec(`UPDATE scheduled_task_actions SET cancelled = true WHERE id = $1 AND account_id=$2 AND fired_at IS NULL`, id, accountID)
	return err
}

// ListScheduledPauses returns pending (unfired, uncancelled) scheduled
// pauses, soonest first — the list_scheduled_pauses tool's backing query.
func (d *DB) ListScheduledPauses(accountID int64) ([]*ScheduledPause, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	rows, err := d.Query(`
SELECT `+scheduledPauseCols+`
FROM scheduled_task_actions
WHERE action = 'pause' AND account_id=$1 AND fired_at IS NULL AND NOT cancelled
ORDER BY run_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScheduledPause
	for rows.Next() {
		p, err := scanScheduledPause(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
