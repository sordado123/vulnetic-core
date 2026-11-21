package db

import (
	"context"
	"strconv"
	"strings"
)

type ExecutionOwner struct{ AccountID, UserID int64 }
type executionOwnerKey struct{}

func WithExecutionOwner(ctx context.Context, accountID, userID int64) context.Context {
	return context.WithValue(ctx, executionOwnerKey{}, ExecutionOwner{accountID, userID})
}
func ExecutionOwnerFrom(ctx context.Context) ExecutionOwner {
	owner, _ := ctx.Value(executionOwnerKey{}).(ExecutionOwner)
	return owner
}

func (d *DB) ledgerAccount(explicit int64, task, session string) any {
	if d.hasAccount {
		return nullIfZero(d.accountID)
	}
	if explicit > 0 {
		return explicit
	}
	if d.RuntimeOnly() {
		if id, err := strconv.ParseInt(task, 10, 64); err == nil && id > 0 {
			scoped := d.runtimeResource("task", id)
			return nullIfZero(scoped.accountID)
		}
		if id, err := strconv.ParseInt(strings.TrimPrefix(session, "conv-"), 10, 64); err == nil && id > 0 {
			scoped := d.runtimeResource("conversation", id)
			return nullIfZero(scoped.accountID)
		}
		return nil
	}
	var owner int64
	if task != "" {
		if d.QueryRow(`SELECT account_id FROM tasks WHERE id::text=$1`, task).Scan(&owner) == nil {
			return owner
		}
	}
	if session != "" {
		if d.QueryRow(`SELECT account_id FROM conversations WHERE 'conv-'||id::text=$1`, session).Scan(&owner) == nil {
			return owner
		}
	}
	return nil // unattributed history stays operator-only
}
