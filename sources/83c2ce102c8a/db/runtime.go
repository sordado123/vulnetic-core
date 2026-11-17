package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
)

// Runtime has no table-owner credential. Every background account uses a pool
// whose physical connections are permanently bound to that account, avoiding GUC leaks.
type runtimePools struct {
	mu    sync.Mutex
	dsn   string
	pools map[int64]*sql.DB
}

func OpenRuntime(dsn string) (*DB, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("app.account_id", "0")
	u.RawQuery = q.Encode()
	dsn = u.String()
	d, err := OpenAppPool(dsn)
	if err != nil {
		return nil, err
	}
	var safe bool
	err = d.QueryRow(`SELECT current_user='vulnetic_app' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND pg_has_role(current_user,relowner,'MEMBER')) AND NOT pg_has_role(current_user,'pg_read_server_files','MEMBER') AND NOT pg_has_role(current_user,'pg_write_server_files','MEMBER') AND NOT pg_has_role(current_user,'pg_execute_server_program','MEMBER') FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		_ = d.Close()
		return nil, errors.New("runtime requires the non-owner RLS application role")
	}
	var version int
	if err = d.QueryRow(`SELECT max(version) FROM beta_migrations`).Scan(&version); err != nil || version < 19 {
		_ = d.Close()
		return nil, errors.New("operator database migration is required before startup")
	}
	d.runtime = &runtimePools{dsn: dsn, pools: make(map[int64]*sql.DB)}
	return d, nil
}
func (d *DB) RuntimeOnly() bool { return d != nil && d.runtime != nil }
func (d *DB) runtimeAccount(id int64) *DB {
	copy := *d
	copy.accountID = id
	copy.hasAccount = true
	d.runtime.mu.Lock()
	defer d.runtime.mu.Unlock()
	pool := d.runtime.pools[id]
	if pool == nil {
		u, err := url.Parse(d.runtime.dsn)
		if err != nil {
			panic("invalid runtime DSN")
		}
		values := u.Query()
		values.Set("app.account_id", strconv.FormatInt(id, 10))
		u.RawQuery = values.Encode()
		pool, err = sql.Open("pgx", u.String())
		if err != nil {
			panic("invalid runtime pool")
		}
		pool.SetMaxOpenConns(4)
		pool.SetMaxIdleConns(2)
		d.runtime.pools[id] = pool
	}
	copy.pool = pool
	copy.Querier = pool
	return &copy
}
func (d *DB) RuntimeAccountIDs() ([]int64, error) {
	rows, err := d.Query(`SELECT id FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (d *DB) runtimeResource(kind string, id int64) *DB {
	if d.runtime == nil || d.hasAccount {
		return d
	}
	var accountID int64
	if d.QueryRow(`SELECT public.vulnetic_runtime_owner($1,$2)`, kind, id).Scan(&accountID) != nil {
		return d.ForAccount(0)
	}
	return d.ForAccount(accountID)
}
func (d *DB) RuntimeForTask(taskID int64) *DB { return d.runtimeResource("task", taskID) }
func (d *DB) runtimeTaskList() ([]*Task, error) {
	ids, err := d.RuntimeAccountIDs()
	if err != nil {
		return nil, err
	}
	var out []*Task
	for _, id := range ids {
		tasks, e := d.ForAccount(id).ListTasks()
		if e != nil {
			return nil, e
		}
		out = append(out, tasks...)
	}
	return out, nil
}
func (d *DB) assertRuntimeState() error {
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM accounts`).Scan(&count); err != nil {
		return fmt.Errorf("runtime database check: %w", err)
	}
	return nil
}
func (d *DB) runtimeAgentIdentity(ctx context.Context, hash []byte) (int64, int64, error) {
	var accountID, targetID int64
	err := d.QueryRowContext(ctx, `SELECT account_id,target_id FROM public.vulnetic_agent_identity($1)`, hash).Scan(&accountID, &targetID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrAgentLease
	}
	return accountID, targetID, err
}

func (d *DB) AccountScoped() bool { return d.hasAccount }
