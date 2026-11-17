// Package db is the PostgreSQL data source for Vulnetic (replacing the old graph
// single-file SQLite). It opens the connection, applies the schema, and seeds
// the built-in agents and variable catalog.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
	"github.com/sordado123/vulnetic/config"
)

//go:embed schema.sql
var baseSchemaSQL string

//go:embed beta.sql
var betaSchemaSQL string

var schemaSQL = baseSchemaSQL + "\n" + llmRecordsSchema + llmRecordsMigrate + llmUsageSchema + "\n" + betaSchemaSQL

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns is the connection pool cap; see the note in Open. It sits well
// below PostgreSQL's default max_connections=100, yet well above the
// application's own nested checkout depth (the startup schema advisory lock
// lets seedBuiltins check out another connection while holding one), so it
// never deadlocks itself.
const maxOpenConns = 32

// maxAppOpenConns is the pool cap for OpenAppPool (RLS-1's non-owner,
// RLS-subject "vulnetic_app" role, used only to serve HTTP requests — see
// db/schema.sql §Z2 and server/tenant_tx.go). Kept separate from, and smaller
// than, maxOpenConns: each in-flight authenticated request holds one app-pool
// connection for its whole duration (not just query time), so budgeted
// alongside the owner pool's 32 the combined total (~52) stays comfortably
// under PostgreSQL's default max_connections=100.
const maxAppOpenConns = 20

// appRoleName is the non-owner Postgres role RLS-1 policies apply to (see
// ensureAppRole and db/schema.sql §Z2). The table-owning role (whatever
// VULNETIC_PG_DSN connects as) is exempt from RLS by default and keeps
// running schema apply + seeding, exactly as before RLS-1.
const appRoleName = "vulnetic_app"

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// isPostgresCatalogRace reports a transient Postgres catalog-concurrency
// error (SQLSTATE XX000, "tuple concurrently updated") seen when multiple
// sessions race to ALTER the same role — e.g. several `go test ./...`
// package binaries each calling db.Open (and so ensureAppRole) against the
// same Postgres instance at once. withSchemaMigrationLock's advisory lock
// already serializes this package's own callers against each other, but it
// cannot serialize against the catalog-level race pg_authid itself exhibits
// under concurrent ALTER ROLE from otherwise-unrelated sessions; retrying
// (same delay table as applySchemaWithRetry) waits it out instead of failing
// a request that did nothing wrong.
func isPostgresCatalogRace(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "XX000" && strings.Contains(pgErr.Message, "concurrently updated")
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if (!isPostgresDeadlock(err) && !isPostgresCatalogRace(err)) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env VULNETIC_PG_DSN (or deprecated ARTEX_PG_DSN) > config file
// (config.json). There is no built-in default — it errors if neither source
// is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// SuffixTestDatabase rewrites the resolved Postgres DSN env var so its
// database name carries the given suffix (vulnetic -> vulnetic_agent). Called
// from package TestMain functions so every go test package runs against its
// own database: parallel package processes then cannot contend on the same
// tables (the under-load deadlock family, #80). No-op when neither
// VULNETIC_PG_DSN nor the deprecated ARTEX_PG_DSN is set — config-file and
// production paths are untouched. Open creates the suffixed database
// automatically (ensureDatabase). Always writes the suffixed value back to
// VULNETIC_PG_DSN (the canonical name), which config.GetenvCompat checks
// first regardless of which name supplied the original value.
func SuffixTestDatabase(suffix string) {
	v := strings.TrimSpace(config.GetenvCompat("VULNETIC_PG_DSN", "ARTEX_PG_DSN"))
	if v == "" {
		return
	}
	u, err := url.Parse(v)
	if err != nil || u.Path == "" || u.Path == "/" {
		return
	}
	u.Path = "/" + strings.TrimPrefix(u.Path, "/") + "_" + suffix
	_ = os.Setenv("VULNETIC_PG_DSN", u.String())
}

// Querier is the subset of *sql.DB / *sql.Tx that every db-package method
// actually calls. Satisfied by both, so a *DB value can be backed by either
// the shared pool (ordinary use) or a single already-open transaction
// (RLS-1's per-request scoping, see NewRequestScoped) without any call-site
// change in the db package.
type Querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// DB wraps either the shared pool (ordinary use) or a single request-scoped
// transaction (RLS-1). PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
//
// accountID/hasAccount matter only for Begin()/BeginTx(): when a db-package
// method opens its own nested sub-transaction (there are ~20 such call sites,
// e.g. db/tasks.go, db/finding_traffic.go) that sub-transaction necessarily
// lands on a *different* pooled connection than whatever Querier this DB value
// already wraps — without re-propagating the account_id GUC onto it, that
// nested transaction would see zero rows under RLS. Begin()/BeginTx() do that
// re-propagation automatically, so every existing `tx, err := d.Begin()` call
// site needs no change.
type DB struct {
	runtime *runtimePools
	Querier
	pool           *sql.DB
	accountID      int64
	hasAccount     bool
	secretKey      []byte
	encryptSecrets bool
	accountKey     func(int64) ([]byte, error)
}

// NewRequestScoped wraps an already-open transaction so every db-package
// method called on the result runs inside that one transaction, and sets the
// RLS GUC (app.account_id) as the transaction's first statement. pool is used
// only by Begin()/BeginTx() to open nested sub-transactions on their own
// connection (never read from directly otherwise). Callers (server/tenant_tx.go)
// must still Commit or Rollback tx themselves — this does not take ownership
// of the transaction's lifecycle, only of what runs inside it.
func NewRequestScoped(pool *sql.DB, tx *sql.Tx, accountID int64) (*DB, error) {
	if err := setAccountGUC(tx, accountID); err != nil {
		return nil, err
	}
	return &DB{Querier: tx, pool: pool, accountID: accountID, hasAccount: true}, nil
}

// setAccountGUC sets the per-transaction app.account_id setting RLS policies
// read via current_setting('app.account_id', true). set_config's third
// argument (is_local=true) scopes it exactly like SET LOCAL: it reverts
// automatically when the transaction ends (commit or rollback), so a pooled
// connection can never leak a stale account_id into a later, unrelated
// request — unlike a plain session-level SET, which would persist on the
// physical connection after it's returned to the pool.
func setAccountGUC(tx *sql.Tx, accountID int64) error {
	if _, err := tx.Exec(`SELECT set_config('app.account_id', $1, true)`, strconv.FormatInt(accountID, 10)); err != nil {
		return fmt.Errorf("set app.account_id GUC: %w", err)
	}
	return nil
}

// Close closes the underlying pool. Safe to call on any *DB value returned by
// Open/OpenAppPool; calling it on a request-scoped *DB (NewRequestScoped)
// would close the whole shared pool, not just that request's transaction —
// callers must never do that (Close belongs to the long-lived *DB the pool
// came from, not to a per-request wrapper around one of its transactions).
func (d *DB) Close() error {
	if d.runtime != nil && !d.hasAccount {
		d.runtime.mu.Lock()
		for _, pool := range d.runtime.pools {
			_ = pool.Close()
		}
		d.runtime.mu.Unlock()
	}
	return d.pool.Close()
}

// Conn checks out a single physical connection from the pool, bypassing
// whatever Querier this DB value wraps. Used only by evidence/testmain_test.go
// today.
func (d *DB) Conn(ctx context.Context) (*sql.Conn, error) { return d.pool.Conn(ctx) }

// BeginTx opens a new transaction on this DB's pool (never on whatever single
// transaction d.Querier might already be — nested transactions always get
// their own connection) and, if this DB value is request-scoped, re-sets the
// account_id GUC on it before returning. See the DB doc comment for why this
// matters for the ~20 internal call sites that open their own sub-transaction.
func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if d.hasAccount {
		if err := setAccountGUC(tx, d.accountID); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

// Begin is the no-argument form of BeginTx, matching every existing
// `tx, err := d.Begin()` call site in the db package.
func (d *DB) Begin() (*sql.Tx, error) { return d.BeginTx(context.Background(), nil) }

func (d *DB) PoolStats() sql.DBStats {
	if d == nil || d.pool == nil {
		return sql.DBStats{}
	}
	stats := d.pool.Stats()
	if d.runtime != nil && !d.hasAccount {
		d.runtime.mu.Lock()
		for _, pool := range d.runtime.pools {
			extra := pool.Stats()
			stats.MaxOpenConnections += extra.MaxOpenConnections
			stats.OpenConnections += extra.OpenConnections
			stats.InUse += extra.InUse
			stats.Idle += extra.Idle
			stats.WaitCount += extra.WaitCount
			stats.WaitDuration += extra.WaitDuration
		}
		d.runtime.mu.Unlock()
	}
	return stats
}

// BeginRequestScoped opens a transaction on d's own pool and wraps it as a
// new request-scoped *DB for accountID (see NewRequestScoped). Intended for
// the app-role pool returned by OpenAppPool — d itself is read-only here,
// never mutated or consumed. The caller (server/tenant_tx.go) owns tx's
// lifecycle and must Commit or Rollback it itself.
func (d *DB) BeginRequestScoped(ctx context.Context, accountID int64) (scoped *DB, tx *sql.Tx, err error) {
	tx, err = d.pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	scoped, err = NewRequestScoped(d.pool, tx, accountID)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	scoped.secretKey = d.secretKey
	scoped.encryptSecrets = d.encryptSecrets
	scoped.accountKey = d.accountKey
	return scoped, tx, nil
}

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql does not limit connections by default: when the pool has no
	// idle connection it unconditionally opens a new one, all the way up to
	// PostgreSQL's max_connections (default 100) before being refused — so
	// peak-load queries get an **error** like `FATAL: sorry, too many clients
	// already`. With a cap, excess queries instead queue waiting for an idle
	// connection — under the same load they become slower rather than failing,
	// and callers no longer have to distinguish "cannot read" from "not there".
	// maxOpenConns must leave headroom for psql / reset-password.sh and any
	// coexisting instances; if max_connections is lowered, lower this too.
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{Querier: sqlDB, pool: sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		// Runs before applySchemaWithRetry: schema.sql's §Z2 GRANT block for
		// appRoleName is guarded by the role already existing, so on the very
		// first startup with VULNETIC_PG_APP_PASSWORD configured, the role
		// must exist before that file is Exec'd for the grants to take effect
		// immediately instead of only after a second restart.
		if err := ensureAppRole(context.Background(), conn, config.PostgresAppPassword()); err != nil {
			return fmt.Errorf("provision app role: %w", err)
		}
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// ensureAppRole creates (if absent) and (re)sets the password of the
// non-owner, RLS-subject role used to serve HTTP requests (RLS-1). It never
// runs anything beyond role/login management — table ownership and schema
// DDL always stay with the connecting (owner) role, never with appRoleName.
// A no-op when password is empty: RLS-1 is then simply not configured in
// this environment (e.g. local dev without VULNETIC_PG_APP_PASSWORD set),
// same as before RLS-1 existed.
//
// The password is never written into schema.sql (a tracked file) — it is
// built into the executed SQL text here, from a Go-resolved value, and
// escaped as a SQL string literal (doubling embedded single quotes) rather
// than passed as a bind parameter, because CREATE/ALTER ROLE's PASSWORD
// clause is DDL syntax, not an expression position Postgres's extended query
// protocol can bind a parameter into.
func ensureAppRole(ctx context.Context, execer schemaExecer, password string) error {
	if password == "" {
		return nil
	}
	for attempt := 0; ; attempt++ {
		err := ensureAppRoleOnce(ctx, execer, password)
		if err == nil || !isPostgresCatalogRace(err) || attempt >= len(schemaDeadlockRetryDelays) {
			return err
		}
		time.Sleep(schemaDeadlockRetryDelays[attempt])
	}
}

func ensureAppRoleOnce(ctx context.Context, execer schemaExecer, password string) error {
	if _, err := execer.ExecContext(ctx, `
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+appRoleName+`') THEN
    CREATE ROLE `+appRoleName+` LOGIN;
  END IF;
END $$;`); err != nil {
		return fmt.Errorf("create role %s: %w", appRoleName, err)
	}
	stmt := fmt.Sprintf(`ALTER ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %s`, appRoleName, quoteSQLLiteral(password))
	if _, err := execer.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("set %s password: %w", appRoleName, err)
	}
	return nil
}

// quoteSQLLiteral escapes s as a single-quoted SQL string literal (doubling
// embedded single quotes — standard SQL escaping, sufficient here since
// Postgres defaults to standard_conforming_strings=on, so a literal backslash
// needs no special handling). Only ever used for Go-controlled secret values
// (the generated/configured app-role password), never for request input.
func quoteSQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// OpenAppPool connects as the non-owner, RLS-subject application role
// (appRoleName) used to serve HTTP requests under RLS-1. Unlike Open, it
// never applies the schema or seeds builtin rows — those must only ever run
// as the table-owning role, never as a role RLS policies apply to (ensureAppRole
// in Open provisions appRoleName itself, before this is ever called).
func OpenAppPool(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(maxAppOpenConns)
	sqlDB.SetMaxIdleConns(maxAppOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres as %s (%s): %w", appRoleName, config.Redact(dsn), err)
	}
	return &DB{Querier: sqlDB, pool: sqlDB}, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // default interactive-shell switch at row creation; ON CONFLICT does not override a user's later manual toggle
	runSeconds            *int // per-run wall-clock limit (seconds) at row creation; nil = use the seed default (1200), 0 = unlimited
}

type promptVar struct{ name, desc, example, source string }

// intp returns a pointer to v, for explicitly setting builtinAgent optional
// fields (e.g. runSeconds).
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). Built-in tools are not stored in the DB;
// only agents + the variable catalog are seeded here.
// Note: the interactive-shell default for planner/worker/mainagent/auto is set
// to true uniformly by the interactive_shell_default_v1 block below (respecting
// later toggles); interactiveShell here is only for new agents that need
// "on by default at row creation".
var builtinAgents = []builtinAgent{
	{"goals", "Goal Decomposer", "goals", "Breaks a penetration testing task's goal into several independent, verifiable sub-goals.", []promptVar{
		{"EngagementDescription", "Task description (test target/background)", "Test the example.com site", "exploration"},
		// Now is a global runtime variable (see server.globalPromptVars) and is no
		// longer defined in each agent's catalog, otherwise withGlobalVars would
		// collide with the global entry when appending.
	}, false, nil},
	{"planner", "Planner", "planner", "Reads the posture, judges goals, and only adds exploration intents when there is a genuinely uncovered new direction (one planning loop per task).", []promptVar{
		{"Goal", "Overall task goal", "Gain admin access to example.com", "exploration"},
		{"AssetSummary", "Asset count/type distribution summary (optional)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "Main", "main", "Human-machine interface: observes progress and turns human intent into hints or high-priority intents.", []promptVar{
		{"Goal", "Current task goal", "Gain admin access to example.com", "exploration"},
		{"AssetSummary", "Initial posture summary (optional)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "Confirmed vulnerability summary (optional)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "Worker", "worker", "Picks up one intent and executes it, writes discovered facts/vulnerabilities back to the knowledge graph, then stops.", []promptVar{
		{"ProxyAddr", "Recorded proxy address (drives the if/else dual wording)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "Worker self-identifier (optional)", "worker-1", "runtime"},
	}, false, nil},
	// Auto: built-in "platform operations" agent. Does not join the pentest
	// orchestration loop; driven from the chat page, operates the platform with tools.
	{"auto", "Auto", "assistant", "Platform operations assistant: manages tasks (create/view/pause/hint) and assets with tools, and can create/modify skills, custom tools, and MCP.", nil, false, nil},
	// Pentest: built-in "solo pentest" agent. Driven from the chat page, it walks the
	// full pentest chain alone from recon to wrap-up, planning, executing and
	// verifying by itself. Interactive shell is on by default.
	{"pentest", "Penetration Testing", "assistant", "Solo pentest agent: single-handedly walks the full chain from recon → attack surface → deep exploitation → verification → wrap-up, with its own planning, execution, and adversarial verification.", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (account_id,key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// After 'Now' was promoted from each agent's catalog to a global runtime
	// variable, old DBs still carry a leftover 'Now' entry for goals, which would
	// collide with the global one (duplicate key in the frontend variable list);
	// clean it up here too.
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (the
	// user enables it when needed), no proxy by default. The traffic-capture
	// toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, account_id)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false, 1)
ON CONFLICT (account_id, name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedCVEVerifyInterceptRules(); err != nil {
		return fmt.Errorf("seed cve-verify intercept rules: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[built-in] Government websites (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[built-in] Government websites (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[built-in] Education websites (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[built-in] Education websites (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin,account_id)
VALUES (true, $1, $2, $3, true,`+d.catalogSQL()+`)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon": {"auto", "pentest", "worker"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1 AND account_id=`+d.catalogSQL()+`
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// ── System-destructive commands (priority 100) ───────────────────────
		{
			name:     "[built-in] Recursive force delete rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "Recursive force delete is forbidden (rm -rf / rm --recursive); it can permanently damage the system or the target machine environment",
			priority: 100,
		},
		{
			name:     "[built-in] Delete critical system directories",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
			action:   "deny",
			message:  "Deleting critical system paths is forbidden",
			priority: 100,
		},
		{
			name:     "[built-in] Disk formatting mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "Formatting disks is forbidden (mkfs)",
			priority: 100,
		},
		{
			name:     "[built-in] Overwrite disk device dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Using dd to overwrite disk devices is forbidden",
			priority: 100,
		},
		{
			name:     "[built-in] Fork bomb",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "Executing a fork bomb is forbidden",
			priority: 100,
		},
		{
			name:     "[built-in] Shutdown / reboot",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "Executing shutdown or reboot commands is forbidden",
			priority: 100,
		},
		{
			name:     "[built-in] Kill all processes",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "kill -9 -1 or killall -9 is forbidden (kills all processes)",
			priority: 100,
		},
		{
			name:     "[built-in] Disk wipe shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "Running shred/wipe erasure against disk devices is forbidden",
			priority: 100,
		},
		{
			name:     "[built-in] Flush firewall rules",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "Flushing firewall rules is forbidden (iptables -F / nft flush)",
			priority: 100,
		},
		// ── Database-destructive operations (priority 90) ────────────────────
		{
			name:     "[built-in] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "DROP operations are forbidden; they can irreversibly destroy database objects",
			priority: 90,
		},
		{
			name:     "[built-in] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "TRUNCATE is forbidden; it can wipe all data in a table",
			priority: 90,
		},
		{
			name:     "[built-in] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "MongoDB drop operations are forbidden",
			priority: 90,
		},
		{
			name:     "[built-in] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "Redis FLUSHALL / FLUSHDB is forbidden; it can wipe all cached data",
			priority: 90,
		},
		// ── Destructive HTTP requests (priority 80) ──────────────────────────
		// The three common ways an Agent sends a DELETE request:
		//   1. curl -X DELETE / --request DELETE (run directly by the Bash tool or written into a script)
		//   2. Python HTTP client .delete() method
		//   3. method: 'DELETE' / method="DELETE" in JS/generic scripts
		{
			name:     "[built-in] curl / wget sending DELETE requests",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "Sending HTTP DELETE requests via curl/wget is forbidden; it may delete data on the target system",
			priority: 80,
		},
		{
			name:     "[built-in] Python HTTP client DELETE (requests/httpx/aiohttp)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "Sending DELETE requests with Python HTTP clients is forbidden",
			priority: 80,
		},
		{
			name:     "[built-in] Declaring the HTTP DELETE method in scripts (JS/generic)",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "Declaring and sending HTTP DELETE requests in scripts is forbidden",
			priority: 80,
		},
		{
			name:     "[built-in] Bulk clear / wipe endpoint paths",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "Calling bulk-clear or destroy-style endpoints is forbidden (/clear /wipe /flush /purge etc.)",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action,account_id)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny',`+d.catalogSQL()+`)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [built-in] rules — the user can
// disable or delete them. The exfil rule ships DISABLED by default (its
// curl/wget/nc pipe pattern mis-fires on legitimate CTF/pentest reverse-shell and
// data-transfer pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedDefaultInterceptRulesV2() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v2"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[built-in] Destructive system commands",
			pattern:  `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
			action:   "deny",
			message:  "Destructive command rejected (rm -rf / / mkfs / dd / fork bomb / shutdown-reboot / overwriting disk devices)",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[built-in] Data exfiltration pipe",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "Suspected data exfiltration pipe rejected (command output piped out via curl/wget/nc)",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action,account_id)
VALUES ($1, $2, $3, 'tool_input', 'regex', $4, $5, $6, false, 60, 'deny',`+d.catalogSQL()+`)
ON CONFLICT DO NOTHING`,
			r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v2", "done")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule. Own flag so it also lands on DBs that already
// ran v1/v2, where editing the v1 seed would have no effect.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

func (d *DB) seedDefaultInterceptRulesV3() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v3"); v == "done" {
		return nil
	}
	const name = "[built-in] Delete-style endpoint paths"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action,account_id)
SELECT $1, true, 80, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'deny',`+d.catalogSQL()+`
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1 AND account_id=`+d.catalogSQL()+`)`,
		name,
		deleteEndpointPathPattern,
		"Calling delete-style endpoints is forbidden (/delete /remove /unlink /erase etc.), regardless of the HTTP method — most apps' delete endpoints can be triggered with GET/POST and will still really delete target data",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_default_rules_v3", "done")
}

// seedCVEVerifyInterceptRules adds an "ask" (not "deny") gate for nuclei runs
// (the cve-verify skill's active-verification step, Peça 3 of the CVE
// intelligence plan). Bash is already in intercept's defaultEnabledTools, so
// any `nuclei ...` command already enters the rule pipeline — this just adds
// a rule that actually matches it. Priority 70, below the destructive deny
// rules (80-100) since this pauses for human approval rather than blocking
// outright. A 5-minute approval timeout auto-denies rather than hanging a
// worker forever on an unanswered prompt.
func (d *DB) seedCVEVerifyInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_cve_verify_rules_v1"); v == "done" {
		return nil
	}
	const name = "[built-in] Nuclei active scan requires approval"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 70, 'tool_input', 'regex', $2, 'ask', $3, true, 300, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		name,
		`\bnuclei\b`,
		"Running nuclei (active vulnerability scanning against a real target) requires approval — confirm the target is in authorized scope and the program allows active scanning before approving",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_cve_verify_rules_v1", "done")
}
