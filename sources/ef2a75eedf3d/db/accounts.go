package db

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// =====================================================================
// Account / user entity layer (multi-tenant SaaS)
// =====================================================================

// LegacyAccountID is the reserved account row schema.sql's multi-tenancy
// migration creates and adopts every pre-existing company/task/asset row
// under. It is also the fallback accountID for code that has no account
// context yet (most of the test suite, and server/auth.go's signJWT shape
// used everywhere auth doesn't matter to the test) — never a substitute for
// threading a real account_id through code that acts on a specific account.
const LegacyAccountID int64 = 1

// Account is a tenant: one customer's companies, tasks and findings are all
// scoped to one account_id. See schema.sql section Z for the isolation model.
type Account struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Role mirrors the users.role CHECK constraint.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// User is one login identity, always under exactly one account.
type User struct {
	ID        int64  `json:"id"`
	AccountID int64  `json:"account_id"`
	Email     string `json:"email"`
	Role      Role   `json:"role"`
	CreatedAt string `json:"created_at"`
}

var (
	ErrAccountSlugConflict = errors.New("account slug already exists")
	ErrEmailConflict       = errors.New("email already in use")
	ErrUserNotFound        = errors.New("user not found")
	ErrPilotFull           = errors.New("pilot account limit reached")
)

// AccountSlug normalizes an account name into a URL-safe, comparison-stable
// key, the same way companyNKey does for company names: lowercase, trimmed,
// internal whitespace collapsed to single hyphens.
func AccountSlug(name string) string {
	fields := strings.Fields(strings.ToLower(name))
	return strings.Join(fields, "-")
}

// CreateAccountWithAdmin creates a new account and its first (admin) user in
// one transaction — there is no such thing as an account with zero users, and
// no such thing as a user that outlives its account's creation.
func (d *DB) CreateAccountWithAdmin(accountName, email, passwordHash string, seed ...func(*DB) error) (account Account, user User, err error) {
	return d.createAccountWithAdmin(accountName, email, passwordHash, 0, seed...)
}

func (d *DB) CreatePilotAccountWithAdmin(accountName, email, passwordHash string, seed ...func(*DB) error) (Account, User, error) {
	return d.createAccountWithAdmin(accountName, email, passwordHash, 5, seed...)
}

func (d *DB) createAccountWithAdmin(accountName, email, passwordHash string, limit int, seed ...func(*DB) error) (account Account, user User, err error) {
	slug := AccountSlug(accountName)
	if slug == "" {
		return Account{}, User{}, errors.New("account name must contain at least one letter or digit")
	}
	tx, err := d.Begin()
	if err != nil {
		return Account{}, User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if limit > 0 {
		// Serialize admission across processes, including simultaneous signups.
		if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741003)`); err != nil {
			return Account{}, User{}, err
		}
		var count int
		countQuery := `SELECT COUNT(DISTINCT account_id) FROM users`
		if d.RuntimeOnly() {
			countQuery = `SELECT public.vulnetic_pilot_account_count()`
		}
		if err = tx.QueryRow(countQuery).Scan(&count); err != nil {
			return Account{}, User{}, err
		}
		if count >= limit {
			return Account{}, User{}, ErrPilotFull
		}
	}

	err = tx.QueryRow(`
INSERT INTO accounts(name, slug) VALUES ($1, $2)
RETURNING id, name, slug, created_at, updated_at`,
		accountName, slug,
	).Scan(&account.ID, &account.Name, &account.Slug, &account.CreatedAt, &account.UpdatedAt)
	if isUniqueViolation(err, "accounts_slug_key") {
		return Account{}, User{}, ErrAccountSlugConflict
	}
	if err != nil {
		return Account{}, User{}, err
	}

	if d.RuntimeOnly() {
		if err = setAccountGUC(tx, account.ID); err != nil {
			return Account{}, User{}, err
		}
	}
	err = tx.QueryRow(`
INSERT INTO users(account_id, email, password_hash, role) VALUES ($1, $2, $3, 'admin')
RETURNING id, account_id, email, role, created_at`,
		account.ID, strings.ToLower(strings.TrimSpace(email)), passwordHash,
	).Scan(&user.ID, &user.AccountID, &user.Email, &user.Role, &user.CreatedAt)
	if isUniqueViolation(err, "uq_users_email") {
		return Account{}, User{}, ErrEmailConflict
	}
	if err != nil {
		return Account{}, User{}, err
	}

	scoped := &DB{Querier: tx, pool: d.pool, accountID: account.ID, hasAccount: true}
	for _, initialize := range seed {
		if err = initialize(scoped); err != nil {
			return Account{}, User{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Account{}, User{}, err
	}
	return account, user, nil
}

func (d *DB) AccountBlocked(accountID int64) (bool, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	blocked, _, err := d.AccountSessionState(accountID)
	return blocked, err
}

func (d *DB) AccountSessionState(accountID int64) (blocked bool, version int64, err error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	err = d.QueryRow(`SELECT blocked,session_version FROM accounts WHERE id=$1`, accountID).Scan(&blocked, &version)
	return
}

// UserByEmail looks up a user and its password hash for login. The hash is
// returned separately from the public User struct so callers cannot forget
// and accidentally serialize it into an API response.
func (d *DB) UserByEmail(email string) (u User, passwordHash string, err error) {
	query := `
SELECT id, account_id, email, password_hash, role, created_at
FROM users WHERE email = $1`
	if d.RuntimeOnly() {
		query = `SELECT id,account_id,email,password_hash,role,created_at FROM public.vulnetic_login($1)`
	}
	err = d.QueryRow(query,
		strings.ToLower(strings.TrimSpace(email)),
	).Scan(&u.ID, &u.AccountID, &u.Email, &passwordHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrUserNotFound
	}
	return u, passwordHash, err
}

// UserByID loads a user by id, scoped to the account the caller's token
// already proved it belongs to — a stolen user id alone is not enough to
// read or change another account's user.
func (d *DB) UserByID(accountID, userID int64) (u User, passwordHash string, err error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	err = d.QueryRow(`
SELECT id, account_id, email, password_hash, role, created_at
FROM users WHERE id = $1 AND account_id = $2`,
		userID, accountID,
	).Scan(&u.ID, &u.AccountID, &u.Email, &passwordHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrUserNotFound
	}
	return u, passwordHash, err
}

// AccountCount reports how many accounts exist — used only to decide whether
// the frontend should offer signup or login first on a brand new install. The
// reserved legacy account (schema.sql §Z) always exists after the schema
// migration runs, so this is never 0 on an upgraded install, only on a truly
// fresh one that has not applied schema.sql yet.
func (d *DB) AccountCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&n)
	return n, err
}

// SetUserPassword updates a user's password hash in place.
func (d *DB) SetUserPassword(userID int64, passwordHash string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("user", userID)
	}
	_, err := d.Exec(`UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, userID)
	return err
}

// isUniqueViolation reports whether err is a Postgres unique_violation
// (SQLSTATE 23505) on the named constraint — CreateAccountWithAdmin hits this
// transaction on two different unique constraints (slug, email) and needs to
// tell them apart to return the right error to the caller.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}
