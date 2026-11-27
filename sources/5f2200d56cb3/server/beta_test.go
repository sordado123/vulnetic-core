package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/db"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestBetaAuthenticationAuditDoesNotStoreCredentials(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	defer d.Close()
	password := "audit-original-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("audit-auth-%d", time.Now().UnixNano())
	a, _, err := d.CreateAccountWithAdmin(name, name+"@example.test", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
	defer d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	s := &Server{m: &Manager{pg: d}, jwtKey: []byte("audit-fixture-signing-key-at-least-32-bytes")}
	login := func(secret string, want int) string {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"email": name + "@example.test", "password": secret})
		r := httptest.NewRequest("POST", "/api/auth/login?secret=must-not-log", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		s.authLogin(w, r)
		if w.Code != want {
			t.Fatalf("login status %d, want %d", w.Code, want)
		}
		var result struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return result.Token
	}
	login("audit-wrong-password", 401)
	token := login(password, 200)
	r := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{"old_password":"audit-original-password","new_password":"audit-new-password"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.authChangePassword(w, r)
	if w.Code != 200 {
		t.Fatalf("password change: %d", w.Code)
	}
	events, err := d.ListAudit(a.ID)
	if err != nil || len(events) != 6 {
		t.Fatal("authentication events missing", len(events), err)
	}
	seenFailure, seenSuccess, seenChange := false, false, false
	for _, event := range events {
		if event.Resource == "/api/auth/login" && event.Status == 401 {
			seenFailure = true
		}
		if event.Resource == "/api/auth/login" && event.Status == 200 {
			seenSuccess = true
		}
		if event.Resource == "/api/auth/change-password" && event.Status == 200 {
			seenChange = true
		}
	}
	if !seenFailure || !seenSuccess || !seenChange {
		t.Fatal("authentication outcome not audited")
	}
	encoded, _ := json.Marshal(events)
	for _, secret := range []string{password, "audit-wrong-password", "audit-new-password", token, "must-not-log", name + "@example.test"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("authentication audit contains credentials or query values")
		}
	}
}

func TestBetaClaimsRejectMissingAccount(t *testing.T) {
	key := []byte("test-key-with-at-least-32-characters")
	token, err := signJWTFor(key, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifyJWT(token, key); ok {
		t.Fatal("token without account was accepted")
	}
	if _, _, ok := accountFromContext(withAccount(httptest.NewRequest("GET", "/", nil), 0).Context()); ok {
		t.Fatal("zero account was accepted")
	}
}

func TestBetaPasswordChangeRevokesSessions(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no PostgreSQL configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	defer d.Close()
	unique := fmt.Sprintf("session-%d", time.Now().UnixNano())
	hash, err := bcrypt.GenerateFromPassword([]byte("initial-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	a, u, err := d.CreateAccountWithAdmin(unique, unique+"@example.test", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
	defer d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
	s := &Server{m: &Manager{pg: d}, jwtKey: []byte("test-signing-key-at-least-32-bytes")}
	token, err := signJWTForPassword(s.jwtKey, a.ID, u.ID, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	handler := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	check := func(token string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/protected", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("session: %d want %d: %s", w.Code, want, w.Body.String())
		}
	}
	check(token, 204)
	claims, _ := verifyJWT(token, s.jwtKey)
	stream, stopStream := s.streamSessionContext(t.Context(), claims, 10*time.Millisecond)
	defer stopStream()
	newHash, _ := bcrypt.GenerateFromPassword([]byte("replacement-password"), bcrypt.MinCost)
	if err := d.SetUserPassword(u.ID, string(newHash)); err != nil {
		t.Fatal(err)
	}
	check(token, 401)
	select {
	case <-stream.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("password change did not close an open stream")
	}
	fresh, _ := signJWTForPassword(s.jwtKey, a.ID, u.ID, string(newHash))
	check(fresh, 204)
	claims, _ = verifyJWT(fresh, s.jwtKey)
	stream, stopFresh := s.streamSessionContext(t.Context(), claims, 10*time.Millisecond)
	defer stopFresh()
	if _, err := d.Exec(`UPDATE accounts SET blocked=true WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	check(fresh, 401)
	select {
	case <-stream.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("account block did not close an open stream")
	}
	if _, err := d.Exec(`UPDATE accounts SET blocked=false WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	check(fresh, 401) // Unblocking must never resurrect sessions issued before the block.
	_, generation, err := d.AccountSessionState(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	afterUnblock, err := signJWTForPassword(s.jwtKey, a.ID, u.ID, string(newHash), generation)
	if err != nil {
		t.Fatal(err)
	}
	check(afterUnblock, 204)
}

func TestAuthLimiterIsBoundedAndExpires(t *testing.T) {
	l := authLimiter{}
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.allow("email", 5, now) {
			t.Fatal("early rejection")
		}
	}
	if l.allow("email", 5, now) {
		t.Fatal("limit bypass")
	}
	if !l.allow("email", 5, now.Add(time.Minute)) {
		t.Fatal("expired entry not released")
	}
	for i := 0; i < 10001; i++ {
		l.allow(time.Unix(int64(i), 0).String(), 1, now.Add(time.Minute))
	}
	if len(l.windows) > 10000 {
		t.Fatal("unbounded limiter")
	}
}

func TestBetaWorkspaceIsolatedAndRooted(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	request := func(account int64, path string) *httptest.ResponseRecorder {
		r := withAccount(httptest.NewRequest("GET", "/api/workspace/read?path="+path, nil), account)
		w := httptest.NewRecorder()
		s.wsRead(w, r)
		return w
	}
	w := httptest.NewRecorder()
	r := withAccount(httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"proof.txt","content":"account-one-proof"}`)), 1)
	s.wsWrite(w, r)
	if w.Code != 200 {
		t.Fatalf("write: %d %s", w.Code, w.Body.String())
	}
	if got := request(1, "proof.txt"); got.Code != 200 || !strings.Contains(got.Body.String(), "account-one-proof") {
		t.Fatalf("own read: %s", got.Body.String())
	}
	if got := request(2, "proof.txt"); got.Code != 404 {
		t.Fatalf("cross-account read: %d", got.Code)
	}
	if got := request(1, "../../jwt.key"); got.Code != 400 {
		t.Fatalf("traversal: %d", got.Code)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.m.dir, "accounts", "1", "artifacts", "escape")
	linkTestDirectory(t, outside, link)
	if got := request(1, "escape/secret.txt"); got.Code == 200 {
		t.Fatal("symlink escaped the workspace")
	}
}

func TestBetaLocalToolsFailClosed(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	s := &Server{}
	for _, kind := range []string{"command", "script", "http"} {
		var result actool.Result
		switch kind {
		case "command":
			result, _ = s.runCommandTool(context.Background(), json.RawMessage(`{"command":"echo unsafe"}`), nil, nil)
		case "script":
			result, _ = s.runScriptTool(context.Background(), "test", json.RawMessage(`{"code":"print('unsafe')"}`), nil, nil)
		case "http":
			result, _ = s.runHTTPTool(context.Background(), json.RawMessage(`{"url":"http://127.0.0.1"}`), nil, nil)
		}
		if !result.IsError {
			t.Errorf("%s allowed local execution", kind)
		}
	}
	result, _ := (remoteOnlyTool{actool.NewBash()}).Call(context.Background(), json.RawMessage(`{"command":"echo unsafe"}`), &actool.ToolContext{Executor: actool.LocalExecutor{}})
	if !result.IsError {
		t.Fatal("explicit LocalExecutor bypassed remote gate")
	}
}

func TestBetaArtifactQuotaBoundaries(t *testing.T) {
	for _, tc := range []struct {
		used, size int64
		reject     bool
	}{
		{0, 20 << 20, false}, {0, (20 << 20) + 1, true}, {(1 << 30) - (20 << 20), 20 << 20, false}, {(1 << 30) - (20 << 20) + 1, 20 << 20, true}, {1 << 30, 0, false}, {0, -1, true},
	} {
		if err := checkArtifactQuota(tc.used, tc.size); (err != nil) != tc.reject {
			t.Errorf("usage %d, write %d: %v", tc.used, tc.size, err)
		}
	}
}

func TestTenantResponseWaitsForCommit(t *testing.T) {
	response := &bufferedTenantResponse{header: make(http.Header), status: 200}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(201)
	response.Write([]byte(`{"ok":true}`))
	dst := httptest.NewRecorder()
	if dst.Body.Len() != 0 {
		t.Fatal("response sent before commit")
	}
	response.send(dst)
	if dst.Code != 201 || dst.Body.String() != `{"ok":true}` {
		t.Fatal("buffered response lost")
	}
}
