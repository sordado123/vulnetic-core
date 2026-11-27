package server

import (
	"github.com/sordado123/vulnetic/config"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const sessionCookie = "vulnetic_session"

// A custom header cannot be sent by a cross-site form; an origin must match when present.
func browserRequest(r *http.Request) bool {
	if r.Header.Get("X-Vulnetic-Request") != "1" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return r.Header.Get("Sec-Fetch-Site") != "cross-site"
}
func (s *Server) browserSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			_, modern := r.Cookie(sessionCookie)
			_, legacy := r.Cookie(authCookie)
			if (modern == nil || legacy == nil || r.URL.Path == "/api/auth/session" || r.URL.Path == "/api/auth/logout") && !browserRequest(r) {
				writeErr(w, 403, "A same-origin browser request is required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	claims, ok := verifyJWT(token, s.jwtKey)
	if !ok {
		writeErr(w, 401, "Session expired; sign in again")
		return
	}
	if !s.sessionCurrent(w, r, claims) {
		return
	}
	user, _, err := s.m.pg.UserByID(claims.AccountID, claims.UserID)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if r.Method == "POST" {
		if claims.ExpiresAt == nil {
			writeErr(w, 401, "Session expiry is required")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: config.SaaSMode() || r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: claims.ExpiresAt.Time, MaxAge: max(1, int(time.Until(claims.ExpiresAt.Time).Seconds()))})
		http.SetCookie(w, &http.Cookie{Name: authCookie, Path: "/", MaxAge: -1, Secure: config.SaaSMode(), HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"id": user.ID, "email": user.Email, "role": user.Role, "account_id": user.AccountID})
}
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookie, authCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: config.SaaSMode() || r.TLS != nil, SameSite: http.SameSiteLaxMode})
	}
	w.WriteHeader(204)
}
