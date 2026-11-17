package server

import (
	"github.com/sordado123/vulnetic/db"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPlatformIngressRejectsExecutorAndSpoofedOrigins(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	t.Setenv("VULNETIC_INGRESS_TRUSTED_PROXIES", "127.0.0.1/32")
	s := &Server{m: &Manager{pg: pg}}
	if err = pg.RecordExecutorOrigin(t.Context(), "198.51.100.19", time.Now().Add(time.Hour)); err != nil {
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
}
