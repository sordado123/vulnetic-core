package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommittedEffectsOnlyAfterSuccess(t *testing.T) {
	for _, status := range []int{200, 400, 503} {
		committed, aborted := false, false
		s := &Server{}
		handler := s.withCommittedEffects(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			afterCommitted(r, func() { committed = true }, func() { aborted = true })
			if committed {
				t.Fatal("effect ran before handler completed")
			}
			w.WriteHeader(status)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/chat", nil))
		if committed != (status < 400) || aborted != (status >= 400) {
			t.Fatalf("status %d: commit=%t abort=%t", status, committed, aborted)
		}
	}
}
func TestBrowserCookieRequestRequiresOriginAndHeader(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		origin, marker string
		want           int
	}{{"https://foreign.test", "1", 403}, {"https://platform.test", "", 403}, {"https://platform.test", "1", 204}} {
		r := httptest.NewRequest("POST", "https://platform.test/api/tasks", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "synthetic"})
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-Vulnetic-Request", tc.marker)
		w := httptest.NewRecorder()
		s.browserSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors") {
			t.Fatal("CSP absent")
		}
	}
}
func TestInvalidJWTKeyNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, jwtKeyFilename)
	original := []byte("invalid")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateJWTKey(dir, t.TempDir()); err == nil {
		t.Fatal("invalid key accepted")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(original) {
		t.Fatal("original key replaced")
	}
}
func TestTaskPageFiltersSortsBeforeSlicing(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/tasks?page=2&size=1&status=paused&sort=id", nil)
	items := []TaskDTO{{ID: "2", Status: "paused"}, {ID: "10", Status: "paused"}, {ID: "12", Status: "running"}}
	page, total, all, counts, err := taskPage(items, request)
	if err != nil || total != 2 || all != 3 || counts["running"] != 1 || len(page) != 1 || page[0].ID != "2" {
		t.Fatalf("wrong page: %v %d %d %v %v", page, total, all, counts, err)
	}
}
