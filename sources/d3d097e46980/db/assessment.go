package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/assessment"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
)

func assessmentSetting(taskID int64, profile string) string {
	return fmt.Sprintf("task.assessment.v1.%d.%s", taskID, profile)
}
func (d *DB) AssessmentCoverage(taskID int64) ([]assessment.Coverage, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return nil, errors.New("authenticated account required")
	}
	if task, err := d.GetTask(taskID); err != nil || task == nil {
		return nil, ErrTaskNotFound
	}
	out := []assessment.Coverage{}
	for _, m := range assessment.Methodologies {
		raw, found, err := d.GetSetting(assessmentSetting(taskID, m.ID))
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		var records map[string]assessment.Coverage
		if json.Unmarshal([]byte(raw), &records) != nil {
			return nil, errors.New("assessment coverage unavailable")
		}
		for _, check := range m.Checks {
			if c, ok := records[check.ID]; ok {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (d *DB) RecordAssessmentCheck(ctx context.Context, taskID int64, c assessment.Coverage) (assessment.Coverage, error) {
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if !d.hasAccount || d.accountID <= 0 {
		return c, errors.New("authenticated account required")
	}
	if !assessment.ValidCheck(c.Profile, c.Check) || !assessment.ValidCheckState(c.State) || len(c.ProofIDs) > 8 || len(c.Note) > 1600 || strings.TrimSpace(c.Note) == "" {
		return c, errors.New("invalid assessment check")
	}
	if task, err := d.GetTask(taskID); err != nil || task == nil {
		return c, ErrTaskNotFound
	}
	observed := c.State == "tested" || c.State == "candidate"
	if observed && len(c.ProofIDs) == 0 {
		return c, errors.New("complete execution proof required for observed coverage")
	}
	for _, id := range c.ProofIDs {
		p, err := d.ExecutionProofByID(d.accountID, id)
		if err != nil || p == nil || p.TaskID == nil || *p.TaskID != taskID {
			return c, errors.New("proof must belong to this task")
		}
		if observed && (p.Failed || p.CaptureIncomplete) {
			return c, errors.New("failed or incomplete proof cannot establish tested coverage")
		}
	}
	c.Note = evidenceredact.Text(d.RedactTaskText(taskID, c.Note))
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(map[string]assessment.Coverage{c.Check: c})
	if err != nil {
		return c, err
	}
	if err = ctx.Err(); err != nil {
		return c, err
	}
	// Merge at the database row, so concurrent workers retain each other's checks.
	_, err = d.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,$3) ON CONFLICT(account_id,key) DO UPDATE SET value=(account_settings.value::jsonb || EXCLUDED.value::jsonb)::text,updated_at=now()`, d.accountID, assessmentSetting(taskID, c.Profile), string(raw))
	return c, err
}
