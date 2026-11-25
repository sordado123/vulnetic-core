package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// LinkConversationProofs records references only; original proof attribution never changes.
func (d *DB) LinkConversationProofs(ctx context.Context, accountID, userID, conversationID, taskID int64, proofIDs []int64, reason string) error {
	reason = strings.TrimSpace(reason)
	if accountID <= 0 || userID <= 0 || conversationID <= 0 || taskID <= 0 || len(proofIDs) == 0 || len(proofIDs) > 20 || len(reason) < 10 || len(reason) > 2000 || (d.hasAccount && d.accountID != accountID) {
		return errors.New("provide an owned conversation, task, 1-20 proof IDs and a reason of 10-2000 characters")
	}
	d = d.ForAccount(accountID)
	tx, nested := d.Querier.(*sql.Tx)
	if !nested {
		var err error
		tx, err = d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	var owned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks t JOIN users u ON u.id=$2 AND u.account_id=t.account_id JOIN conversations c ON c.id=$3 AND c.account_id=t.account_id WHERE t.id=$4 AND t.account_id=$1 AND t.deleted_at IS NULL AND c.agent_key IN ('auto','pentest'))`, accountID, userID, conversationID, taskID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return errors.New("conversation or task not found")
	}
	seen := map[int64]bool{}
	for _, id := range proofIDs {
		if id <= 0 || seen[id] {
			return errors.New("invalid or duplicate proof ID")
		}
		seen[id] = true
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_proofs WHERE id=$1 AND account_id=$2 AND conversation_id=$3 AND task_id IS NULL AND verification_run_id IS NULL)`, id, accountID, conversationID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return errors.New("proof does not belong to this standalone conversation")
		}
	}
	for _, id := range proofIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_execution_proof_links(account_id,task_id,proof_id,user_id,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, accountID, taskID, id, userID, reason); err != nil {
			return err
		}
	}
	if !nested {
		return tx.Commit()
	}
	return nil
}

// Restore only chat execution bindings; leave other role and customer customizations alone.
func (d *DB) RestoreChatBash() error {
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
	result, err := tx.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,'chat_bash_proof_links_v1','true') ON CONFLICT DO NOTHING`, d.accountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		for _, role := range []string{"auto", "pentest"} {
			if _, err = tx.Exec(`UPDATE tools SET agents=agents || to_jsonb($2::text),updated_at=now() WHERE account_id=$1 AND system AND key IN ('Bash','sleep') AND NOT (agents ? $2::text)`, d.accountID, role); err != nil {
				return err
			}
		}
	}
	if !nested {
		return tx.Commit()
	}
	return nil
}
