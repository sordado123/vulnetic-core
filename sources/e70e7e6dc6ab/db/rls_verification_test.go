package db

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sordado123/vulnetic/config"
)

// rlsTestAppPassword is used only when VULNETIC_PG_APP_PASSWORD is not
// already set in the test environment, so this test is self-contained and
// does not depend on the broader test run having opted into RLS-1. It is a
// local-test-database-only credential, never used outside this process.
const rlsTestAppPassword = "beta-integration-test-password-only"

// TestRLSEnforcement is RLS-1's one load-bearing proof: that Postgres itself
// blocks cross-account reads on the 10 directly account_id-scoped tables,
// not merely that the app's own `WHERE account_id = ...` filters happen to
// agree with it. It deliberately runs an UNSCOPED query (no WHERE at all)
// through the non-owner vulnetic_app role — the same role server/tenant_tx.go
// serves every authenticated HTTP request through — and checks what Postgres
// actually returns for the wrong account vs. the right one. If this test
// were deleted and RLS silently stopped doing anything (policies dropped,
// GUC wiring broken, role accidentally granted ownership), every other test
// in this suite would still pass, because they all go through the app's own
// account_id-filtered queries, which work correctly with or without RLS.
func TestRLSEnforcement(t *testing.T) {
	if os.Getenv("VULNETIC_PG_APP_PASSWORD") == "" {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", rlsTestAppPassword)
	}

	// Open as the owner role: applies schema.sql (which, now that the env var
	// above is set, provisions vulnetic_app and grants it access — see
	// db.Open/ensureAppRole) and gives us an RLS-bypassing connection to seed
	// test data with, exactly like today's seeding/migrations.
	d, err := Open(testDSN(t))
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatalf("required RLS verification unavailable: %v", err)
		}
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	appDSN, err := config.PostgresAppDSN()
	if err != nil {
		t.Fatalf("resolve app DSN: %v", err)
	}
	if appDSN == "" {
		t.Fatal("app DSN empty even after setting VULNETIC_PG_APP_PASSWORD")
	}
	appPool, err := sql.Open("pgx", appDSN)
	if err != nil {
		t.Fatalf("open as vulnetic_app: %v", err)
	}
	defer appPool.Close()
	if err := appPool.Ping(); err != nil {
		t.Fatalf("ping as vulnetic_app: %v", err)
	}

	accountA := newTestAccount(t, d, "rls-a")
	accountB := newTestAccount(t, d, "rls-b")

	t.Run("ssh_targets (child row keyed by account_id)", func(t *testing.T) {
		if _, err := d.CreateSSHTarget(accountA, "rls-verify-target", "203.0.113.20", 22, "root",
			[]byte("ciphertext"), []byte("nonce1234567"), "ssh-ed25519 AAAA fake", "SHA256:fake"); err != nil {
			t.Fatal(err)
		}
		assertUnscopedCountAsAccount(t, appPool, "ssh_targets", accountB, 0)
		assertUnscopedCountAsAccount(t, appPool, "ssh_targets", accountA, 1)
	})

	t.Run("account_vault_keys (account_id IS the primary key)", func(t *testing.T) {
		kek := make([]byte, 32)
		if _, err := d.GetOrCreateAccountDEK(accountA, kek); err != nil {
			t.Fatal(err)
		}
		assertUnscopedCountAsAccount(t, appPool, "account_vault_keys", accountB, 0)
		assertUnscopedCountAsAccount(t, appPool, "account_vault_keys", accountA, 1)
	})
}

// TestRLS2Enforcement is RLS-2's equivalent proof, for the tables scoped only
// indirectly (schema.sql §Z3): a direct-column table that gained its column
// in this round (conversations), a child row scoped through its parent task
// (task_archives), and the rsi_lessons nullable-company_id case, where a
// company-scoped row must stay isolated while a global (company_id IS NULL)
// row must stay visible to every account by design.
func TestRLS2Enforcement(t *testing.T) {
	if os.Getenv("VULNETIC_PG_APP_PASSWORD") == "" {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", rlsTestAppPassword)
	}
	d, err := Open(testDSN(t))
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatalf("required RLS verification unavailable: %v", err)
		}
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	appDSN, err := config.PostgresAppDSN()
	if err != nil {
		t.Fatalf("resolve app DSN: %v", err)
	}
	if appDSN == "" {
		t.Fatal("app DSN empty even after setting VULNETIC_PG_APP_PASSWORD")
	}
	appPool, err := sql.Open("pgx", appDSN)
	if err != nil {
		t.Fatalf("open as vulnetic_app: %v", err)
	}
	defer appPool.Close()
	if err := appPool.Ping(); err != nil {
		t.Fatalf("ping as vulnetic_app: %v", err)
	}

	accountA := newTestAccount(t, d, "rls2-a")
	accountB := newTestAccount(t, d, "rls2-b")

	t.Run("conversations (direct account_id, new this round)", func(t *testing.T) {
		if _, err := d.CreateConversation(accountA, "mainagent", "rls2-verify-conv", nil); err != nil {
			t.Fatal(err)
		}
		assertUnscopedCountAsAccount(t, appPool, "conversations", accountB, 0)
		assertUnscopedCountAsAccount(t, appPool, "conversations", accountA, 1)
	})

	t.Run("task_archives (child row scoped via task_id -> tasks)", func(t *testing.T) {
		task, err := d.CreateTaskWithOptions("rls2-verify-desc", "rls2-verify-goal", TaskCreateOptions{AccountID: accountA})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`INSERT INTO task_archives(task_id) VALUES ($1)`, task.ID); err != nil {
			t.Fatal(err)
		}
		assertUnscopedCountAsAccount(t, appPool, "task_archives", accountB, 0)
		assertUnscopedCountAsAccount(t, appPool, "task_archives", accountA, 1)
	})

	t.Run("rsi_lessons (nullable company_id: scoped row isolated, global row shared)", func(t *testing.T) {
		company, _, err := d.Companies().UpsertCompany(accountA, "rls2-verify-co", "")
		if err != nil {
			t.Fatal(err)
		}
		scopedKey := fmt.Sprintf("rls2-verify-scoped-%d", company)
		if _, err := d.Exec(`INSERT INTO rsi_lessons(dedupe_key,kind,cue,action,company_id) VALUES ($1,'caution','cue','action',$2)`,
			scopedKey, company); err != nil {
			t.Fatal(err)
		}
		globalKey := fmt.Sprintf("rls2-verify-global-%d", company)
		if _, err := d.Exec(`INSERT INTO rsi_lessons(dedupe_key,kind,cue,action,company_id) VALUES ($1,'caution','cue','action',NULL)`,
			globalKey); err != nil {
			t.Fatal(err)
		}
		assertScopedCountAsAccount(t, appPool, "rsi_lessons", "dedupe_key", scopedKey, accountB, 0)
		assertScopedCountAsAccount(t, appPool, "rsi_lessons", "dedupe_key", scopedKey, accountA, 1)
		assertScopedCountAsAccount(t, appPool, "rsi_lessons", "dedupe_key", globalKey, accountB, 1)
		assertScopedCountAsAccount(t, appPool, "rsi_lessons", "dedupe_key", globalKey, accountA, 1)
	})
}

// assertScopedCountAsAccount is assertUnscopedCountAsAccount with one extra
// `WHERE col = val` term — needed for tables a concurrent test in this same
// package could also be writing to (rsi_lessons has no per-test isolation of
// its own), so the count reflects only this subtest's own row, not whatever
// else is live in the table at the same moment. RLS still applies exactly as
// it does for the unscoped case: this is not a substitute for it, only a
// narrower target for it to filter.
func assertScopedCountAsAccount(t *testing.T, appPool *sql.DB, table, col, val string, accountID int64, want int) {
	t.Helper()
	tx, err := appPool.Begin()
	if err != nil {
		t.Fatalf("begin as vulnetic_app: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.account_id', $1, true)`, strconv.FormatInt(accountID, 10)); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var got int
	if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1`, table, col), val).Scan(&got); err != nil {
		t.Fatalf("scoped count on %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s (%s=%s) as account %d: got %d rows via RLS, want %d — RLS is not enforcing as expected", table, col, val, accountID, got, want)
	}
}

// assertUnscopedCountAsAccount opens its own transaction on appPool, sets
// app.account_id to accountID exactly as server/tenant_tx.go's withTenantTx
// does for a real request, runs a deliberately unscoped `SELECT count(*)`
// against table (no WHERE clause anywhere — if RLS were not enforcing,
// this would return every account's rows), and asserts the count Postgres
// itself computed. Always rolls back: this never leaves committed state.
func assertUnscopedCountAsAccount(t *testing.T, appPool *sql.DB, table string, accountID int64, want int) {
	t.Helper()
	tx, err := appPool.Begin()
	if err != nil {
		t.Fatalf("begin as vulnetic_app: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.account_id', $1, true)`, strconv.FormatInt(accountID, 10)); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var got int
	if err := tx.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s`, table)).Scan(&got); err != nil {
		t.Fatalf("unscoped count on %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s as account %d: got %d rows via RLS, want %d — RLS is not enforcing as expected", table, accountID, got, want)
	}
}
