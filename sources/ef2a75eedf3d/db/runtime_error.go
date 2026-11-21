package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
)

var ErrRuntimeOwner = errors.New("runtime owner resolution unavailable")

// A failed owner lookup must fail every subsequent operation, including Scan.
type scopeFailure struct{ err error }

func (f scopeFailure) Exec(string, ...any) (sql.Result, error) { return nil, f.err }
func (f scopeFailure) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, f.err
}
func (f scopeFailure) Query(string, ...any) (*sql.Rows, error) { return nil, f.err }
func (f scopeFailure) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, f.err
}
func (f scopeFailure) QueryRow(query string, args ...any) *sql.Row {
	return f.QueryRowContext(context.Background(), query, args...)
}
func (f scopeFailure) QueryRowContext(ctx context.Context, _ string, _ ...any) *sql.Row {
	// database/sql owns Row's error field; the connector fails before any IO.
	pool := sql.OpenDB(f)
	defer pool.Close()
	return pool.QueryRowContext(ctx, "")
}
func (f scopeFailure) Connect(context.Context) (driver.Conn, error) { return nil, f.err }
func (f scopeFailure) Driver() driver.Driver                        { return f }
func (f scopeFailure) Open(string) (driver.Conn, error)             { return nil, f.err }
