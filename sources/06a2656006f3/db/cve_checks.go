package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/cvecheck"
	"time"
)

type CVEAuthorization struct {
	ID            int64           `json:"id"`
	AccountID     int64           `json:"-"`
	UserID        int64           `json:"-"`
	TaskID        int64           `json:"task_id"`
	AssetID       int64           `json:"asset_id"`
	ExecutorID    int64           `json:"executor_id"`
	RecipeID      string          `json:"recipe_id"`
	RecipeDigest  string          `json:"recipe_digest"`
	TargetURL     string          `json:"target_url"`
	Target        cvecheck.Target `json:"-"`
	ExpiresAt     time.Time       `json:"expires_at"`
	RemainingRuns int             `json:"remaining_runs"`
}
type CVECheckRun struct {
	ID              int64           `json:"id"`
	AccountID       int64           `json:"-"`
	UserID          int64           `json:"-"`
	AuthorizationID *int64          `json:"authorization_id,omitempty"`
	TaskID          *int64          `json:"task_id,omitempty"`
	AssetID         *int64          `json:"asset_id,omitempty"`
	ExecutorID      int64           `json:"executor_id"`
	RecipeID        string          `json:"recipe_id"`
	RecipeDigest    string          `json:"recipe_digest"`
	TargetURL       string          `json:"target_url"`
	Status          string          `json:"status"`
	Outcome         string          `json:"outcome"`
	ProofID         *int64          `json:"proof_id,omitempty"`
	Summary         json.RawMessage `json:"summary,omitempty"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
}

func (d *DB) CreateCVEAuthorization(ctx context.Context, a CVEAuthorization) (*CVEAuthorization, error) {
	if a.AccountID <= 0 || a.UserID <= 0 || a.TaskID <= 0 || a.AssetID <= 0 || a.ExecutorID <= 0 || a.RemainingRuns < 1 || a.RemainingRuns > 3 {
		return nil, fmt.Errorf("explicit authorization attribution is required")
	}
	d = d.ForAccount(a.AccountID)
	recipe, err := cvecheck.Lookup(a.RecipeID)
	if err != nil || recipe.Digest() != a.RecipeDigest {
		return nil, fmt.Errorf("verifier revision unavailable")
	}
	if err = a.Target.Validate(); err != nil {
		return nil, err
	}
	if a.TargetURL != a.Target.URL {
		return nil, fmt.Errorf("authorization origin mismatch")
	}
	raw, err := json.Marshal(a.Target)
	if err != nil {
		return nil, err
	}
	sealed, err := d.sealSecret(a.AccountID, string(raw))
	if err != nil {
		return nil, err
	}
	var limit time.Time
	err = d.QueryRowContext(ctx, `SELECT s.agent_expires_at FROM tasks t JOIN assets a ON a.id=$3 JOIN users u ON u.id=$5 JOIN ssh_targets s ON s.id=$4 JOIN execution_agents e ON e.target_id=s.id WHERE t.id=$2 AND t.account_id=$1 AND a.account_id=$1 AND u.account_id=$1 AND s.account_id=$1 AND e.account_id=$1 AND a.url=$6 AND t.id=ANY(a.task_ids) AND t.ssh_target_id=s.id AND e.revoked_at IS NULL AND e.runtime_hash IS NOT NULL AND s.agent_expires_at>now()`, a.AccountID, a.TaskID, a.AssetID, a.ExecutorID, a.UserID, a.TargetURL).Scan(&limit)
	if err != nil {
		return nil, fmt.Errorf("owned task, linked asset and current executor are required")
	}
	max := time.Now().Add(15 * time.Minute)
	if limit.Before(max) {
		max = limit
	}
	if a.ExpiresAt.IsZero() || a.ExpiresAt.After(max) {
		a.ExpiresAt = max
	}
	if !a.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("authorization expired")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `INSERT INTO cve_authorizations(account_id,user_id,task_id,asset_id,executor_id,recipe_id,recipe_digest,target_url,payload,expires_at,remaining_runs) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, a.AccountID, a.UserID, a.TaskID, a.AssetID, a.ExecutorID, a.RecipeID, a.RecipeDigest, a.TargetURL, sealed, a.ExpiresAt, a.RemainingRuns).Scan(&a.ID)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_audit(account_id,user_id,action,resource,status) VALUES($1,$2,'CVE_AUTHORIZE',$3,201)`, a.AccountID, a.UserID, fmt.Sprintf("/cve-authorizations/%d", a.ID)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return &a, nil
}
func (d *DB) CVEAuthorization(ctx context.Context, accountID, id int64) (*CVEAuthorization, error) {
	d = d.ForAccount(accountID)
	var a CVEAuthorization
	var payload string
	err := d.QueryRowContext(ctx, `SELECT id,account_id,user_id,COALESCE(task_id,0),COALESCE(asset_id,0),executor_id,recipe_id,recipe_digest,target_url,payload,expires_at,remaining_runs FROM cve_authorizations WHERE id=$1 AND account_id=$2`, id, accountID).Scan(&a.ID, &a.AccountID, &a.UserID, &a.TaskID, &a.AssetID, &a.ExecutorID, &a.RecipeID, &a.RecipeDigest, &a.TargetURL, &payload, &a.ExpiresAt, &a.RemainingRuns)
	if err != nil {
		return nil, err
	}
	raw, err := d.openSecret(accountID, payload)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(raw), &a.Target); err != nil {
		return nil, err
	}
	return &a, nil
}
func (d *DB) StartCVECheck(ctx context.Context, accountID, userID, authorizationID, taskID int64) (*CVECheckRun, *CVEAuthorization, error) {
	a, err := d.CVEAuthorization(ctx, accountID, authorizationID)
	if err != nil {
		return nil, nil, err
	}
	recipe, err := cvecheck.Lookup(a.RecipeID)
	if err != nil || recipe.Digest() != a.RecipeDigest {
		return nil, nil, fmt.Errorf("verifier changed; new authorization required")
	}
	if a.TaskID != taskID {
		return nil, nil, sql.ErrNoRows
	}
	d = d.ForAccount(accountID)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks t JOIN assets a ON a.id=$3 JOIN users u ON u.id=$4 JOIN ssh_targets s ON s.id=$5 JOIN execution_agents e ON e.target_id=s.id WHERE t.id=$2 AND t.account_id=$1 AND a.account_id=$1 AND u.account_id=$1 AND s.account_id=$1 AND e.account_id=$1 AND a.url=$6 AND t.id=ANY(a.task_ids) AND t.ssh_target_id=s.id AND e.revoked_at IS NULL AND e.runtime_hash IS NOT NULL AND s.agent_expires_at>now())`, accountID, taskID, a.AssetID, userID, a.ExecutorID, a.TargetURL).Scan(&valid)
	if err != nil || !valid {
		return nil, nil, fmt.Errorf("execution ownership or lease changed")
	}
	var remaining int
	err = tx.QueryRowContext(ctx, `UPDATE cve_authorizations SET remaining_runs=remaining_runs-1 WHERE id=$1 AND account_id=$2 AND expires_at>now() AND remaining_runs>0 AND task_id=$3 RETURNING remaining_runs`, authorizationID, accountID, taskID).Scan(&remaining)
	if err != nil {
		return nil, nil, fmt.Errorf("authorization expired or exhausted")
	}
	r := CVECheckRun{AccountID: accountID, UserID: userID, AuthorizationID: &a.ID, TaskID: &a.TaskID, AssetID: &a.AssetID, ExecutorID: a.ExecutorID, RecipeID: a.RecipeID, RecipeDigest: a.RecipeDigest, TargetURL: a.TargetURL, Status: "running", Outcome: "inconclusive"}
	err = tx.QueryRowContext(ctx, `INSERT INTO cve_check_runs(account_id,user_id,authorization_id,task_id,asset_id,executor_id,recipe_id,recipe_digest,target_url,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'running') RETURNING id,started_at`, accountID, userID, authorizationID, taskID, a.AssetID, a.ExecutorID, a.RecipeID, a.RecipeDigest, a.TargetURL).Scan(&r.ID, &r.StartedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("executor already has a verification running or storage unavailable")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_audit(account_id,user_id,action,resource,status) VALUES($1,$2,'CVE_EXECUTE_START',$3,200)`, accountID, userID, fmt.Sprintf("/cve-checks/%d", r.ID)); err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &r, a, nil
}
func (d *DB) FinishCVECheck(ctx context.Context, r *CVECheckRun, result cvecheck.Result, proofID *int64) error {
	if r == nil || r.AccountID <= 0 {
		return fmt.Errorf("verification attribution required")
	}
	d = d.ForAccount(r.AccountID)
	if result.RecipeID != r.RecipeID || result.RecipeDigest != r.RecipeDigest || result.Target != r.TargetURL {
		return fmt.Errorf("verifier result attribution mismatch")
	}
	if result.Outcome == "reproduced" && (!result.DecisiveProof() || proofID == nil) {
		return fmt.Errorf("reproduction requires complete controls and durable execution proof")
	}
	// Only summary metadata enters list APIs; complete bytes live in the encrypted proof artifact.
	summary, _ := json.Marshal(map[string]any{"reason": result.Reason, "healthy": result.Healthy, "control_valid": result.ControlValid, "negative_clean": result.NegativeClean, "reproductions": result.Reproductions, "requests": len(result.Observations), "traffic_capture": "unavailable"})
	sealed, err := d.sealSecret(r.AccountID, string(summary))
	if err != nil {
		return err
	}
	if proofID != nil {
		var owned bool
		err = d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_proofs WHERE id=$1 AND account_id=$2 AND verification_run_id=$3 AND task_id=$4 AND asset_id=$5 AND executor_id=$6 AND NOT failed AND NOT capture_incomplete AND full_artifact_id<>'')`, *proofID, r.AccountID, r.ID, r.TaskID, r.AssetID, r.ExecutorID).Scan(&owned)
		if err != nil || !owned {
			return fmt.Errorf("proof does not belong to this verifier run")
		}
	}
	switch result.Outcome {
	case "reproduced", "not_reproduced", "inconclusive", "not_applicable", "blocked", "error":
	default:
		return fmt.Errorf("invalid verification outcome")
	}
	res, err := d.ExecContext(ctx, `UPDATE cve_check_runs SET status='completed',outcome=$3,payload=$4,proof_id=$5,finished_at=now() WHERE id=$1 AND account_id=$2 AND status='running'`, r.ID, r.AccountID, result.Outcome, sealed, proofID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return fmt.Errorf("verification ended or unavailable")
	}
	return nil
}
func (d *DB) CVEChecks(accountID, taskID int64) ([]CVECheckRun, error) {
	d = d.ForAccount(accountID)
	rows, err := d.Query(`SELECT id,account_id,user_id,authorization_id,task_id,asset_id,executor_id,recipe_id,recipe_digest,target_url,status,outcome,payload,proof_id,started_at,finished_at FROM cve_check_runs WHERE account_id=$1 AND task_id=$2 ORDER BY id DESC LIMIT 100`, accountID, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CVECheckRun{}
	for rows.Next() {
		var r CVECheckRun
		var payload string
		if err = rows.Scan(&r.ID, &r.AccountID, &r.UserID, &r.AuthorizationID, &r.TaskID, &r.AssetID, &r.ExecutorID, &r.RecipeID, &r.RecipeDigest, &r.TargetURL, &r.Status, &r.Outcome, &payload, &r.ProofID, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		if payload != "" {
			value, e := d.openSecret(accountID, payload)
			if e != nil {
				return nil, e
			}
			r.Summary = json.RawMessage(value)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (d *DB) InterruptCVEChecks() error {
	if d.RuntimeOnly() && !d.hasAccount {
		ids, err := d.RuntimeAccountIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err = d.ForAccount(id).InterruptCVEChecks(); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := d.Exec(`UPDATE cve_check_runs SET status='completed',outcome='inconclusive',finished_at=now() WHERE status='running' AND ` + d.tenantSQL(""))
	return err
}
func (d *DB) ValidateFindingCheckProofs(ctx context.Context, accountID, findingID int64, ids []int64) error {
	d = d.ForAccount(accountID)
	var selected *int64
	for _, id := range ids {
		p, err := d.ExecutionProofByID(accountID, id)
		if err != nil {
			return err
		}
		if p.VerificationRunID == nil {
			continue
		}
		if selected != nil && *selected != *p.VerificationRunID {
			return fmt.Errorf("select proofs of one exact CVE verification run")
		}
		selected = p.VerificationRunID
		var owned bool
		err = d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cve_check_runs r JOIN findings f ON f.id=$3 WHERE r.id=$1 AND r.account_id=$2 AND f.account_id=$2 AND r.task_id=f.task_id AND f.asset_ids @> jsonb_build_array(r.asset_id) AND r.proof_id=$4 AND r.status='completed' AND r.outcome='reproduced')`, *p.VerificationRunID, accountID, findingID, id).Scan(&owned)
		if err != nil || !owned {
			return fmt.Errorf("CVE verification proof does not match this finding's asset, task and successful run")
		}
	}
	if selected != nil {
		for _, id := range ids {
			p, _ := d.ExecutionProofByID(accountID, id)
			if p == nil || p.VerificationRunID == nil {
				return errors.New("CVE verification proofs cannot be mixed with unrelated execution output")
			}
		}
	}
	return nil
}
