package server

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPlatformIngressRejectsExecutorAndSpoofedOrigins(t *testing.T) {
	testPlatformIngressSession(t, false)
}

func TestRuntimePlatformIngressWithSession(t *testing.T) {
	testPlatformIngressSession(t, true)
}

func testPlatformIngressSession(t *testing.T, runtimeOnly bool) {
	if runtimeOnly {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", "beta-integration-test-password-only")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	t.Setenv("VULNETIC_INGRESS_TRUSTED_PROXIES", "127.0.0.1/32")
	s := &Server{m: &Manager{pg: pg}, jwtKey: []byte("synthetic-ingress-signing-key-only")}
	if runtimeOnly {
		appDSN, err := config.PostgresAppDSN()
		if err != nil {
			t.Fatal(err)
		}
		runtimeDB, err := db.OpenRuntime(appDSN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtimeDB.Close() })
		s.m.pg = runtimeDB
	}
	if err = pg.RecordExecutorOrigin(t.Context(), "198.51.100.19", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ingress-%d", time.Now().UnixNano())
	account, user, err := pg.CreateAccountWithAdmin(name, name+"@fixture.invalid", "synthetic-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM users WHERE account_id=$1`, account.ID)
		_, _ = pg.Exec(`DELETE FROM accounts WHERE id=$1`, account.ID)
	})
	token, err := signJWTForPassword(s.jwtKey, account.ID, user.ID, "synthetic-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := verifyJWT(token, s.jwtKey)
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, expired).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner, err := signJWTForPassword(s.jwtKey, account.ID+1000000, user.ID, "synthetic-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	h := s.withPlatformIngress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "198.51.100.20:0" && r.RemoteAddr != "198.51.100.19:0" {
			t.Errorf("unverified rate-limit identity: %s", r.RemoteAddr)
		}
		w.WriteHeader(204)
	}))
	for _, tt := range []struct {
		peer, source, path string
		status             int
	}{
		{"127.0.0.1:1234", "198.51.100.19", "/api/tasks", 403},
		{"127.0.0.1:1234", "198.51.100.19", "/chat/", 403},
		{"127.0.0.1:1234", "198.51.100.19", "/agent/connect", 204},
		{"127.0.0.1:1234", "198.51.100.19", "/agent/v1/control", 403},
		{"127.0.0.1:1234", "198.51.100.20", "/api/tasks", 204},
		{"203.0.113.4:1234", "198.51.100.20", "/api/tasks", 403},
		{"127.0.0.1:1234", "", "/api/tasks", 403},
	} {
		r := httptest.NewRequest("GET", tt.path, nil)
		r.RemoteAddr = tt.peer
		r.Header.Set("CF-Connecting-IP", tt.source)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s %s: got %d want %d", tt.peer, tt.path, w.Code, tt.status)
		}
	}
	request := func(token, transport, path string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("CF-Connecting-IP", "198.51.100.19")
		switch transport {
		case "cookie":
			r.AddCookie(&http.Cookie{Name: authCookie, Value: token})
		case "query":
			query := r.URL.Query()
			query.Set("token", token)
			r.URL.RawQuery = query.Encode()
		default:
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d want %d", transport, path, w.Code, want)
		}
	}
	request(token, "cookie", "/chat/", 204)
	request(token, "cookie", "/_next/static/test.js", 204)
	request(token, "bearer", "/api/tasks", 204)
	request(token, "query", "/api/tasks/1/stream", 204)
	request(expiredToken, "cookie", "/chat/", 403)
	request(token+"corrupted", "bearer", "/api/tasks", 403)
	request(wrongOwner, "cookie", "/chat/", 401)
	legacy, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request(legacy, "cookie", "/chat/", 401)
	// Browser-shaped headers alone never establish a session.
	r := httptest.NewRequest("GET", "/chat/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("CF-Connecting-IP", "198.51.100.19")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", "https://vulnetic.site")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("spoofed browser headers bypassed authentication")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = "203.0.113.4:1234"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("valid session bypassed trusted ingress validation")
	}
	if _, err = pg.Exec(`UPDATE accounts SET blocked=true WHERE id=$1`, account.ID); err != nil {
		t.Fatal(err)
	}
	request(token, "cookie", "/chat/", 401)
	if _, err = pg.Exec(`UPDATE accounts SET blocked=false,session_version=session_version+1 WHERE id=$1`, account.ID); err != nil {
		t.Fatal(err)
	}
	request(token, "bearer", "/api/tasks", 401)
	_, version, err := pg.AccountSessionState(account.ID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := signJWTForPassword(s.jwtKey, account.ID, user.ID, "synthetic-password-hash", version)
	if err != nil {
		t.Fatal(err)
	}
	request(current, "cookie", "/chat/", 204)
	if _, err = pg.Exec(`UPDATE users SET password_hash='changed-synthetic-hash' WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	request(current, "cookie", "/chat/", 401)
	blocked, err := pg.ExecutorOriginBlocked(t.Context(), "198.51.100.19")
	if err != nil || !blocked {
		t.Fatal("session exception erased the executor origin block", err)
	}
	request("", "bearer", "/api/tasks", 403)
	offline, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err = offline.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := (&Server{m: &Manager{pg: offline}, jwtKey: s.jwtKey}).withPlatformIngress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("unavailable policy admitted a request") }))
	r = httptest.NewRequest("GET", "/chat/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("CF-Connecting-IP", "198.51.100.19")
	r.AddCookie(&http.Cookie{Name: authCookie, Value: token})
	w = httptest.NewRecorder()
	unavailable.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "execution_policy_unavailable") {
		t.Fatal("unavailable policy did not fail closed")
	}
}
