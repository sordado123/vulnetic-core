package server

import (
	"github.com/sordado123/vulnetic/config"
	"net/http"
)

func (s *Server) withAccountAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.SaaSMode() {
			next.ServeHTTP(w, r)
			return
		}
		accountID, userID, ok := accountFromContext(r.Context())
		if !ok || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		response, finish, ok := s.beginAccountAudit(w, r, accountID, userID)
		if !ok {
			return
		}
		next.ServeHTTP(response, r)
		finish()
	})
}

func (s *Server) beginAccountAudit(w http.ResponseWriter, r *http.Request, accountID, userID int64) (http.ResponseWriter, func(), bool) {
	if !config.SaaSMode() {
		return w, func() {}, true
	}
	resource := r.URL.EscapedPath() // No bodies, query values, email addresses or credentials.
	if err := s.m.pg.RecordAudit(accountID, userID, r.Method, resource, http.StatusContinue); err != nil {
		writeErr(w, 503, "Audit storage unavailable")
		return nil, nil, false
	}
	response := &bufferedTenantResponse{header: make(http.Header), status: http.StatusOK}
	return response, func() {
		if failure := recover(); failure != nil {
			panic(failure)
		}
		if err := s.m.pg.RecordAudit(accountID, userID, r.Method, resource, response.status); err != nil {
			writeErr(w, 503, "Audit result could not be persisted")
			return
		}
		response.send(w)
	}, true
}

func (s *Server) accountAudit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	events, err := pg.ListAudit(mustRequestAccount(r))
	if err != nil {
		writeErr(w, 503, "Audit storage unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"events": events})
}
