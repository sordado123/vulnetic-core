package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// A model verdict is a proposal; only a reviewer can confirm it against this run's proofs.
func (d *DB) ReviewFindingRetest(ctx context.Context, accountID, userID, findingID, retestID int64, proofIDs []int64, steps string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	steps = strings.TrimSpace(steps)
	if accountID <= 0 || userID <= 0 || len(steps) < 10 || len(steps) > 16000 || len(proofIDs) == 0 || len(proofIDs) > 20 || (d.hasAccount && d.accountID != accountID) {
		return errors.New("provide reproduction steps, execution proofs and this account's authenticated reviewer")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owned bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND account_id=$2)`, userID, accountID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return errors.New("reviewer does not belong to account")
	}
	var evidence, summary string
	var version int64
	if err = tx.QueryRowContext(ctx, `SELECT evidence,summary,evidence_version FROM findings WHERE id=$1 AND account_id=$2 FOR UPDATE`, findingID, accountID).Scan(&evidence, &summary, &version); err != nil {
		return ErrFindingNotFound
	}
	var conversationID *int64
	var verdict, status string
	var unchanged bool
	if err = tx.QueryRowContext(ctx, `SELECT conversation_id,verdict,status,
 snapshot->'finding'->>'evidence'= $3 AND snapshot->'finding'->>'summary'=$4 AND (snapshot->'finding'->>'evidence_version')::bigint=$5
 FROM finding_retests WHERE id=$1 AND finding_id=$2 FOR UPDATE`, retestID, findingID, evidence, summary, version).Scan(&conversationID, &verdict, &status, &unchanged); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if status != "completed" || (verdict != "fixed" && verdict != "reproduced") || conversationID == nil {
		return errors.New("only a completed decisive retest can be reviewed")
	}
	if !unchanged {
		return errors.New("source evidence changed after this retest; start a new retest")
	}
	for _, id := range proofIDs {
		var proofID int64
		var checkID *int64
		if err = tx.QueryRowContext(ctx, `SELECT id,verification_run_id FROM execution_proofs WHERE id=$1 AND account_id=$2 AND conversation_id=$3 AND NOT failed AND NOT capture_incomplete AND (NOT truncated OR (schema_version>=2 AND full_artifact_id<>'')) FOR SHARE`, id, accountID, conversationID).Scan(&proofID, &checkID); err != nil {
			return errors.New("execution proof does not belong to this retest run")
		}
		if checkID != nil {
			var payload, outcome string
			var sameBaseline bool
			err = tx.QueryRowContext(ctx, `SELECT r.payload,r.outcome,EXISTS(
                SELECT 1 FROM finding_verifications v JOIN cve_check_runs original ON original.id=v.check_run_id
                WHERE v.finding_id=$3 AND v.account_id=$2 AND original.recipe_id=r.recipe_id
                  AND original.target_url=r.target_url AND original.asset_id=r.asset_id AND original.task_id=r.task_id
                  AND original.outcome='reproduced' AND v.evidence_version=$4)
                FROM cve_check_runs r WHERE r.id=$1 AND r.account_id=$2 AND r.proof_id=$5 AND r.status='completed'`, *checkID, accountID, findingID, version, id).Scan(&payload, &outcome, &sameBaseline)
			if err != nil || !sameBaseline {
				return errors.New("controlled retest must match the original verified target, asset and recipe")
			}
			raw, e := d.openSecret(accountID, payload)
			if e != nil {
				return e
			}
			var controls struct {
				Healthy       bool `json:"healthy"`
				ControlValid  bool `json:"control_valid"`
				NegativeClean bool `json:"negative_clean"`
				Reproductions int  `json:"reproductions"`
			}
			if json.Unmarshal([]byte(raw), &controls) != nil || !controls.Healthy || !controls.ControlValid || !controls.NegativeClean {
				return errors.New("retest controls are incomplete")
			}
			if verdict == "fixed" && (outcome != "not_reproduced" || controls.Reproductions != 0) || verdict == "reproduced" && (outcome != "reproduced" || controls.Reproductions != 2) {
				return errors.New("retest proposal contradicts its controlled execution")
			}
		}
	}
	raw, err := json.Marshal(proofIDs)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO finding_retest_reviews(retest_id,account_id,user_id,steps,proof_ids) VALUES($1,$2,$3,$4,$5)`, retestID, accountID, userID, steps, string(raw)); err != nil {
		return err
	}
	if verdict == "fixed" {
		if _, _, _, _, err = SetFindingStatusTx(ctx, tx, findingID, FindingFixed); err != nil {
			return err
		}
	}
	return tx.Commit()
}
