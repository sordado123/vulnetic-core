package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"strings"
)

// reqPGContextKey is the context key withTenantTx stashes the request-scoped
// *db.DB under. Unexported so only this package can read or write it.
type reqPGContextKey struct{}

// withTenantTx is RLS-1's central piece: for every authenticated request
// (requireAuth has already verified the JWT and stashed its claims by the
// time this runs — see the middleware chain in server/server.go's Handler),
// it opens one transaction on the non-owner, RLS-subject app pool, sets the
// app.account_id GUC Postgres policies read (db.NewRequestScoped), and
// stashes the result where s.pg(w, r) picks it up — every existing
// `pg := s.pg(w)` call site then transparently runs inside that one
// request-scoped transaction instead of the shared pool, with no change
// beyond the pg(w) -> pg(w, r) signature.
//
// Routes requireAuth exempts (/api/auth/*, /api/health) have no account in
// context, so they are let through unchanged: s.pg(w, r) falls back to the
// owner pool (m.pg) for them, exactly as every handler behaved before RLS-1
// — necessary since login/signup legitimately need cross-account visibility
// (e.g. looking a user up by email before their account is known), which the
// RLS-protected app pool could never provide.
//
// Commits on success or a 4xx response (a handler may legitimately persist
// partial state before a later validation fails); rolls back on a >=500
// response or a panic, re-panicking afterward so the panic still reaches the
// standard recovery path above this middleware. A defer guards every exit
// path, including panic, so a transaction (and its pooled connection) is
// never left open.
func (s *Server) withTenantTx(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Filesystem requests enforce ownership directly and must not retain a SQL connection during IO.
		if strings.HasPrefix(r.URL.Path, "/api/workspace/") || r.URL.Path == "/api/skills" || strings.HasPrefix(r.URL.Path, "/api/skills/") {
			h.ServeHTTP(w, r)
			return
		}
		// Streams authorize their resource explicitly and query in short operations.
		if r.Method == http.MethodGet && (strings.HasSuffix(r.URL.Path, "/stream") || strings.HasSuffix(r.URL.Path, "/events") || r.URL.Path == "/api/workspace/download") {
			h.ServeHTTP(w, r)
			return
		}
		// Remote handshakes/tools are bounded separately and must not hold pool connections.
		if strings.HasSuffix(r.URL.Path, "/verification/execute") || strings.HasPrefix(r.URL.Path, "/api/execution-proofs/") || strings.HasPrefix(r.URL.Path, "/api/ssh-targets/") || strings.HasPrefix(r.URL.Path, "/api/execution-agents/") || strings.HasSuffix(r.URL.Path, "/refresh") || (r.URL.Path == "/api/tools/custom/test" || r.URL.Path == "/api/chat/upload" || r.URL.Path == "/api/llm/profiles/test" || r.URL.Path == "/api/llm/models" || (strings.HasPrefix(r.URL.Path, "/api/notify/channels/") && strings.HasSuffix(r.URL.Path, "/test"))) {
			h.ServeHTTP(w, r)
			return
		}
		if s.m.pgApp == nil {
			// RLS-1 not configured in this environment (VULNETIC_PG_APP_PASSWORD
			// unset) — behave exactly as before RLS-1 existed.
			h.ServeHTTP(w, r)
			return
		}
		accountID, _, ok := accountFromContext(r.Context())
		if !ok {
			h.ServeHTTP(w, r)
			return
		}
		reqPG, tx, err := s.m.pgApp.BeginRequestScoped(r.Context(), accountID)
		if err != nil {
			log.Printf("[tenant-tx] begin: %v", err)
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), reqPGContextKey{}, reqPG)
		sw := &bufferedTenantResponse{header: make(http.Header), status: http.StatusOK}

		committed := false
		defer func() {
			if p := recover(); p != nil {
				_ = tx.Rollback()
				panic(p)
			}
			if !committed {
				_ = tx.Rollback()
			}
		}()
		h.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status >= 500 {
			_ = tx.Rollback()
			sw.send(w)
			return
		}
		if err := tx.Commit(); err != nil {
			log.Printf("[tenant-tx] commit: %v", err)
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		committed = true
		sw.send(w)
	})
}

// Success cannot reach the client before the transaction commits.
type bufferedTenantResponse struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func (w *bufferedTenantResponse) Header() http.Header { return w.header }
func (w *bufferedTenantResponse) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
}
func (w *bufferedTenantResponse) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}
func (w *bufferedTenantResponse) send(dst http.ResponseWriter) {
	for key, values := range w.header {
		dst.Header()[key] = values
	}
	dst.WriteHeader(w.status)
	_, _ = dst.Write(w.body.Bytes())
}
