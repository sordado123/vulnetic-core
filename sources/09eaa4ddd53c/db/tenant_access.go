package db

import (
	"context"
	"database/sql"
	"errors"
	"github.com/sordado123/vulnetic/sidequestion"
)

func (d *DB) OwnsIntercept(ctx context.Context, accountID, id int64) (bool, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	var owned bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM intercept_pending WHERE id=$1 AND account_id=$2)`, id, accountID).Scan(&owned)
	return accountID > 0 && owned, err
}

func (d *DB) SideRequestForAccount(ctx context.Context, accountID int64, id string) (*sidequestion.Exchange, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	e, err := scanSide(d.QueryRowContext(ctx, `SELECT `+sideCols+` FROM side_question_requests q
WHERE q.id=$1 AND EXISTS(SELECT 1 FROM side_question_sessions s
LEFT JOIN tasks t ON t.id=s.task_id LEFT JOIN conversations c ON c.id=s.conversation_id
WHERE s.session_key=q.session_key AND COALESCE(t.account_id,c.account_id)=$2
AND (t.account_id IS NULL OR c.account_id IS NULL OR t.account_id=c.account_id))`, id, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &e, err
}
