package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/config"
)

// Attack chains (#24): the agent's declared narrative of how separate findings
// compose into an escalation. A chain is an ordered list of steps, each pointing
// at a finding with the rationale that links it to the next; the overall narrative
// and severity describe the combined impact. The findings carry the evidence — a
// chain only asserts the causal story the exploration graph's planner lineage
// cannot.

type AttackChainStepInput struct {
	FindingID int64  `json:"finding_id"`
	Rationale string `json:"rationale"`
}

type AttackChainInput struct {
	TaskID    int64
	Title     string
	Narrative string
	Severity  string
	Steps     []AttackChainStepInput
}

type AttackChainStep struct {
	Position  int    `json:"position"`
	FindingID int64  `json:"finding_id"`
	Rationale string `json:"rationale"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Name      string `json:"name,omitempty"`
}

type AttackChain struct {
	ID        int64             `json:"id"`
	TaskID    *int64            `json:"task_id,omitempty"`
	Title     string            `json:"title"`
	Narrative string            `json:"narrative"`
	Severity  string            `json:"severity"`
	CreatedAt time.Time         `json:"created_at"`
	Steps     []AttackChainStep `json:"steps"`
}

var attackChainSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// RecordAttackChain stores an agent-declared attack chain for a task. Every step
// must reference a finding of the same task and account, or nothing is written: a
// chain that reaches across tenants or tasks is rejected, not silently dropped.
func (s *ExplorationStore) RecordAttackChain(ctx context.Context, in AttackChainInput) (int64, error) {
	in.Title = strings.TrimSpace(in.Title)
	in.Narrative = strings.TrimSpace(in.Narrative)
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	if in.TaskID <= 0 {
		return 0, errors.New("attack chains require a task context")
	}
	if in.Title == "" || in.Narrative == "" {
		return 0, errors.New("an attack chain needs a title and a narrative")
	}
	if !attackChainSeverities[in.Severity] {
		return 0, errors.New("severity must be one of critical, high, medium, low")
	}
	if len(in.Steps) < 2 {
		return 0, errors.New("an attack chain needs at least two finding steps that compose")
	}
	if len(in.Steps) > 50 {
		return 0, errors.New("too many steps in one chain")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	accountID, err := accountIDForTaskQ(tx, in.TaskID)
	if err != nil {
		return 0, err
	}
	actor := ExecutionOwnerFrom(ctx)
	if config.SaaSMode() && actor.AccountID <= 0 {
		return 0, errors.New("execution account is required")
	}
	if actor.AccountID != 0 && actor.AccountID != accountID {
		return 0, errors.New("attack chain account mismatch")
	}
	for _, st := range in.Steps {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1 AND account_id=$2 AND task_id=$3)`, st.FindingID, accountID, in.TaskID).Scan(&ok); err != nil {
			return 0, err
		}
		if !ok {
			return 0, errors.New("every step must reference a finding of this task")
		}
	}
	var id int64
	if err := tx.QueryRow(`INSERT INTO attack_chains(account_id,exploration_id,task_id,title,narrative,severity) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		accountID, s.expID, nullIfZero(in.TaskID), in.Title, in.Narrative, in.Severity).Scan(&id); err != nil {
		return 0, err
	}
	for i, st := range in.Steps {
		if _, err := tx.Exec(`INSERT INTO attack_chain_steps(chain_id,position,finding_id,rationale) VALUES($1,$2,$3,$4)`, id, i, st.FindingID, strings.TrimSpace(st.Rationale)); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// AttackChains returns the attack chains recorded for a task, newest first, each
// with its ordered steps resolved to the finding's current title/severity/summary.
func (d *DB) AttackChains(ctx context.Context, accountID, taskID int64) ([]AttackChain, error) {
	d = d.ForAccount(accountID)
	rows, err := d.QueryContext(ctx, `SELECT id,task_id,title,narrative,severity,created_at FROM attack_chains WHERE account_id=$1 AND task_id=$2 ORDER BY id DESC`, accountID, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chains []AttackChain
	for rows.Next() {
		var c AttackChain
		if err := rows.Scan(&c.ID, &c.TaskID, &c.Title, &c.Narrative, &c.Severity, &c.CreatedAt); err != nil {
			return nil, err
		}
		chains = append(chains, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return chains, nil
	}
	byID := make(map[int64]*AttackChain, len(chains))
	for i := range chains {
		byID[chains[i].ID] = &chains[i]
	}
	srows, err := d.QueryContext(ctx, `SELECT s.chain_id,s.position,s.finding_id,s.rationale,COALESCE(f.summary,''),COALESCE(f.severity,''),COALESCE(f.name,'')
	 FROM attack_chain_steps s JOIN attack_chains c ON c.id=s.chain_id AND c.account_id=$1
	 LEFT JOIN findings f ON f.id=s.finding_id
	 WHERE c.task_id=$2 ORDER BY s.chain_id,s.position`, accountID, taskID)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var chainID int64
		var st AttackChainStep
		if err := srows.Scan(&chainID, &st.Position, &st.FindingID, &st.Rationale, &st.Summary, &st.Severity, &st.Name); err != nil {
			return nil, err
		}
		if c := byID[chainID]; c != nil {
			c.Steps = append(c.Steps, st)
		}
	}
	return chains, srows.Err()
}

// One-time binding update leaves subsequent customer edits and disabled flags intact.
func (d *DB) EnableAttackChainPlanner() error {
	if !d.hasAccount || d.accountID <= 0 {
		return errors.New("account required")
	}
	tx, nested := d.Querier.(*sql.Tx)
	if !nested {
		var err error
		tx, err = d.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	result, err := tx.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,'attack_chain_planner_v1','true') ON CONFLICT DO NOTHING`, d.accountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		_, err = tx.Exec(`UPDATE tools SET agents=agents || '"planner"'::jsonb,updated_at=now() WHERE account_id=$1 AND system AND key='record_attack_chain' AND NOT(agents ? 'planner')`, d.accountID)
		if err != nil {
			return err
		}
	}
	if !nested {
		return tx.Commit()
	}
	return nil
}
