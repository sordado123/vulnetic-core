package server

import (
	"context"
	"net/http"
)

type committedEffectsKey struct{}
type committedEffects struct{ commit, abort []func() }

// Both the database commit and audit confirmation precede any background execution.
func (s *Server) withCommittedEffects(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		effects := &committedEffects{}
		done := false
		defer func() {
			if !done {
				for _, f := range effects.abort {
					f()
				}
			}
		}()
		response := &bufferedTenantResponse{header: make(http.Header), status: http.StatusOK}
		next.ServeHTTP(response, r.WithContext(context.WithValue(r.Context(), committedEffectsKey{}, effects)))
		if response.status < 400 {
			for _, f := range effects.commit {
				f()
			}
			done = true
		}
		response.send(w)
	})
}
func afterCommitted(r *http.Request, commit, abort func()) {
	if effects, ok := r.Context().Value(committedEffectsKey{}).(*committedEffects); ok {
		effects.commit = append(effects.commit, commit)
		effects.abort = append(effects.abort, abort)
		return
	}
	commit()
}
