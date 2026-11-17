package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
)

const (
	jwtKeyFilename = "jwt.key"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// authCookie is the browser storage key shared with the frontend
	// (web/src/lib/auth.ts's TOKEN_KEY) and the extension.
	authCookie = "vulnetic_token"

	// The lower bound matches the setup page's frontend validation — validation that
	// lives only in the frontend is as good as none: hitting the API directly bypasses
	// it. The upper bound is bcrypt's hard limit: past 72 bytes GenerateFromPassword returns ErrPasswordTooLong; rejecting early beats a cryptic "password encryption failed".
	minPasswordRunes = 8
	maxPasswordBytes = 72
	// minAccountNameRunes keeps AccountSlug from ever normalizing to the empty
	// string (a single emoji or punctuation-only name would).
	minAccountNameRunes = 2

	// legacyAccountID is the reserved account row schema.sql's multi-tenancy
	// migration creates (and adopts every pre-existing company/task row under).
	// signJWT — the single-operator-shaped call used by every existing test —
	// issues tokens scoped to it, so none of those tests needed to change to
	// learn about accounts.
	legacyAccountID = 1
)

// errDataSourceUnavailable is the uniform reply when a password-related read fails.
// These handlers must never mistake a failed read for "not set": authInit once let an
// unauthenticated request through on a database error, overwriting the admin password.
const errDataSourceUnavailable = "Data source temporarily unavailable, please retry later"

// validatePassword returns an empty string when passing, otherwise a reason ready to show the user.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// Preserve the original bytes during legacy migration; any read/write failure is fatal.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			data, readErr := os.ReadFile(legacy)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				return nil, fmt.Errorf("read legacy JWT key: %w", readErr)
			}
			if readErr == nil {
				if len(strings.TrimSpace(string(data))) < 32 {
					return nil, errors.New("legacy JWT key is invalid; restore the original key")
				}
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if errors.Is(err, os.ErrExist) {
					return loadOrCreateJWTKey(keyDir, dataDir)
				}
				if err != nil {
					return nil, err
				}
				_, err = f.Write(data)
				if err == nil {
					err = f.Sync()
				}
				closeErr := f.Close()
				if err == nil {
					err = closeErr
				}
				if err != nil {
					return nil, err
				}
				if err = os.Remove(legacy); err != nil {
					return nil, fmt.Errorf("remove legacy JWT key from workspace: %w", err)
				}
			}
		} else if statErr != nil {
			return nil, statErr
		}
	}

	if data, err := os.ReadFile(path); err == nil {
		if len(strings.TrimSpace(string(data))) < 32 {
			return nil, errors.New("stored JWT key is invalid; restore the original key")
		}
		return []byte(strings.TrimSpace(string(data))), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read JWT key: %w", err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateJWTKey(keyDir, dataDir)
	}
	if err != nil {
		return nil, fmt.Errorf("create JWT key: %w", err)
	}
	_, err = f.Write(buf)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("persist JWT key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// vulneticClaims binds a session to its account, user and current password version.
type vulneticClaims struct {
	jwt.RegisteredClaims
	AccountID       int64  `json:"account_id"`
	UserID          int64  `json:"user_id"`
	PasswordVersion string `json:"password_version,omitempty"`
	AccountVersion  int64  `json:"account_version,omitempty"`
}

// signJWT issues a 7-day HS256 token scoped to the reserved legacy account.
// Every test file in this package (and any single-operator deployment that
// never calls authInit/authLogin's multi-tenant path) uses this shape — kept
// unchanged on purpose so introducing accounts did not require touching 20+
// test files that have nothing to do with tenancy.
func signJWT(key []byte) (string, error) {
	return signJWTFor(key, legacyAccountID, 0)
}

// signJWTFor issues a 7-day HS256 token for a specific account/user — the
// shape authInit and authLogin actually use once a real account exists.
func signJWTFor(key []byte, accountID, userID int64) (string, error) {
	return signJWTForPassword(key, accountID, userID, "")
}

func signJWTForPassword(key []byte, accountID, userID int64, hash string, accountVersions ...int64) (string, error) {
	version := ""
	if hash != "" {
		version = passwordVersion(hash)
	}
	var accountVersion int64
	if len(accountVersions) > 0 {
		accountVersion = accountVersions[0]
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, vulneticClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		AccountID:       accountID,
		UserID:          userID,
		PasswordVersion: version,
		AccountVersion:  accountVersion,
	}).SignedString(key)
}

// verifyJWT returns the token's claims when tokenStr is a valid, non-expired
// HS256 token signed with key.
func verifyJWT(tokenStr string, key []byte) (*vulneticClaims, bool) {
	claims := &vulneticClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, false
	}
	return claims, claims.AccountID > 0 && claims.UserID >= 0
}

// extractToken reads the JWT from Authorization: Bearer header,
// authCookie cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if c, err := r.Cookie(authCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if !config.SaaSMode() {
		return r.URL.Query().Get("token")
	}
	return ""
}

// authContextKey is the context key requireAuth stashes verified claims
// under. Unexported so only this package can read or write it.
type authContextKey struct{}

// accountFromContext reads the verified, nonzero owner of a request.
func accountFromContext(ctx context.Context) (accountID, userID int64, ok bool) {
	c, ok := ctx.Value(authContextKey{}).(*vulneticClaims)
	if !ok || c.AccountID <= 0 {
		return 0, 0, false
	}
	return c.AccountID, c.UserID, true
}

// requireAccountID reads the account id requireAuth already verified and
// stashed in the request context, writing 401 and returning ok=false if it is
// somehow missing (requireAuth did not run, or ran and failed open — neither
// should happen on an authenticated route, but a handler must never silently
// fall back to any default account rather than reject the request).
func requireAccountID(w http.ResponseWriter, r *http.Request) (accountID int64, ok bool) {
	accountID, _, ok = accountFromContext(r.Context())
	if !ok {
		writeErr(w, 401, "Unauthorized")
		return 0, false
	}
	return accountID, true
}

// taskForAccount looks up a task by id, scoped to the account recorded in
// the request's own verified token. Every HTTP handler that pulls a task id
// out of the URL (not internal engine code acting on a task it already has)
// must use this instead of calling s.m.Task directly: without it, a valid
// token from account B could pause, delete, or message a task that belongs
// to account A just by knowing or guessing its id — same shape as the
// companies IDOR this package already closed, just for tasks. A task that
// exists but belongs to a different account is reported exactly like one
// that does not exist (ok=false), not a 403, so the response never confirms
// another account's task id is in use.
func (s *Server) taskForAccount(r *http.Request, id string) (*Task, bool) {
	t, ok := s.m.Task(id)
	if !ok {
		return nil, false
	}
	accountID, _, authOK := accountFromContext(r.Context())
	if !authOK || t.AccountID != accountID {
		return nil, false
	}
	return t, true
}

// Empty/active selection belongs to the authenticated account.
func (s *Server) taskForAccountOrActive(r *http.Request, raw string) (*Task, bool) {
	accountID, _, ok := accountFromContext(r.Context())
	if !ok {
		return nil, false
	}
	if raw == "" || raw == "active" {
		if task := s.m.ActiveTaskForAccount(accountID); task != nil {
			raw = task.ID
		}
	}
	return s.taskForAccount(r, raw)
}

// findingForAccount looks up a finding by id, scoped to the request's own
// account — same shape and same reason as taskForAccount, for the sibling
// resource. A finding that exists but belongs to a different account is
// reported as not found, not 403.
func (s *Server) findingForAccount(r *http.Request, id int64) (*db.DBFinding, bool) {
	accountID, _, ok := accountFromContext(r.Context())
	if !ok {
		return nil, false
	}
	f, err := s.m.pg.ForAccount(accountID).GetFinding(id)
	return f, err == nil && f != nil && f.AccountID == accountID
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "Unauthorized")
			return
		}
		claims, ok := verifyJWT(tok, s.jwtKey)
		if !ok {
			writeErr(w, 401, "token is invalid or expired")
			return
		}
		if !s.sessionCurrent(w, r, claims) {
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, claims)
		ctx = db.WithExecutionOwner(ctx, claims.AccountID, claims.UserID)
		if claims.UserID > 0 && r.Method == http.MethodGet && (strings.HasSuffix(p, "/stream") || strings.HasSuffix(p, "/events")) {
			var cancel context.CancelFunc
			ctx, cancel = s.streamSessionContext(ctx, claims, 5*time.Second)
			defer cancel()
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GET /api/auth/status — reports whether any account exists yet. In the old
// single-operator shape this gated /setup vs /login on one global password;
// in the multi-tenant shape it answers the same question for the same reason
// (a brand new, still-empty database, the moment install finishes) — once any
// account exists, new operators sign up their own rather than being routed to
// a global setup step. A read failure must answer 503, not initialized:false:
// on initialized:false the frontend ships the user to /setup, and wrapping a
// database outage in a 200 risks that path when it should not be reachable.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	n, err := pg.AccountCount()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": n > 0, "saas_mode": config.SaaSMode()})
}

// POST /api/auth/init — creates a new account and its first (admin) user.
// Unlike the single-operator install this rewrote, "already set" is no longer
// a global condition (there is no single password to have already set) — a
// signup is only rejected for a conflicting account name or email, so this
// endpoint stays open for a second, third, ... customer to sign up, not just
// the first.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	var req struct {
		AccountName string `json:"account_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if !s.allowAuthAttempt(w, r, req.Email) {
		return
	}
	if config.SaaSMode() && !config.PilotEmailAllowed(req.Email) {
		writeErr(w, 403, "Registration is restricted to invited pilot accounts")
		return
	}
	if utf8.RuneCountInString(strings.TrimSpace(req.AccountName)) < minAccountNameRunes {
		writeErr(w, 400, fmt.Sprintf("Account name must be at least %d characters", minAccountNameRunes))
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeErr(w, 400, "Email cannot be empty")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	create := pg.CreateAccountWithAdmin
	if config.SaaSMode() {
		create = pg.CreatePilotAccountWithAdmin
	}
	account, user, err := create(req.AccountName, req.Email, string(hash), s.seedAccountCatalog)
	switch {
	case errors.Is(err, db.ErrPilotFull):
		writeErr(w, 403, "Pilot registration is full")
		return
	case errors.Is(err, db.ErrAccountSlugConflict):
		writeErr(w, 409, "An account with this name already exists")
		return
	case errors.Is(err, db.ErrEmailConflict):
		writeErr(w, 409, "Email already in use")
		return
	case err != nil:
		// Anything other than the two client-correctable conflicts above is an
		// infra problem (closed pool, unreachable Postgres, ...), not a bad
		// request — 503 tells the client to retry instead of reporting its
		// signup as rejected.
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	w, finish, ok := s.beginAccountAudit(w, r, account.ID, user.ID)
	if !ok {
		return
	}
	defer finish()
	tok, err := signJWTForPassword(s.jwtKey, account.ID, user.ID, string(hash))
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the current user's password.
// Requires a valid token (this route is under /api/auth/* which requireAuth
// exempts, so the token is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	claims, ok := verifyJWT(extractToken(r), s.jwtKey)
	if !ok {
		writeErr(w, 401, "Unauthorized")
		return
	}
	if !s.sessionCurrent(w, r, claims) {
		return
	}
	w, finish, ok := s.beginAccountAudit(w, r, claims.AccountID, claims.UserID)
	if !ok {
		return
	}
	defer finish()
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	_, hash, err := pg.UserByID(claims.AccountID, claims.UserID)
	if errors.Is(err, db.ErrUserNotFound) {
		writeErr(w, 401, "Unauthorized")
		return
	}
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "Current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	if err := pg.SetUserPassword(claims.UserID, string(newHash)); err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates email/password and returns a JWT scoped
// to that user's account. Replaces the single-operator version's fixed
// username check: every user row has its own email now, so login looks one
// up instead of comparing against a constant.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if !s.allowAuthAttempt(w, r, req.Email) {
		return
	}
	user, hash, err := pg.UserByEmail(req.Email)
	if errors.Is(err, db.ErrUserNotFound) {
		writeErr(w, 401, "Incorrect email or password")
		return
	}
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	w, finish, ok := s.beginAccountAudit(w, r, user.AccountID, user.ID)
	if !ok {
		return
	}
	defer finish()
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect email or password")
		return
	}
	blocked, accountVersion, err := pg.AccountSessionState(user.AccountID)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if blocked {
		writeErr(w, 401, "Incorrect email or password")
		return
	}
	tok, err := signJWTForPassword(s.jwtKey, user.AccountID, user.ID, hash, accountVersion)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
