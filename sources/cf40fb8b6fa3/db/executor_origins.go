package db

import (
	"context"
	"net/netip"
	"time"
)

// Origin retention is independent of executor lifetime/deletion to prevent a revoke/delete bypass.
func (d *DB) RecordExecutorOrigin(ctx context.Context, source string, until time.Time) error {
	ip, err := netip.ParseAddr(source)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO executor_origins(ip,blocked_until) VALUES($1::inet,$2) ON CONFLICT(ip) DO UPDATE SET blocked_until=GREATEST(executor_origins.blocked_until,excluded.blocked_until),last_seen=now()`, ip.Unmap().String(), until)
	return err
}
func (d *DB) ExecutorOriginBlocked(ctx context.Context, source string) (bool, error) {
	ip, err := netip.ParseAddr(source)
	if err != nil {
		return false, err
	}
	var blocked bool
	err = d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM executor_origins WHERE ip=$1::inet AND blocked_until>now())`, ip.Unmap().String()).Scan(&blocked)
	return blocked, err
}
