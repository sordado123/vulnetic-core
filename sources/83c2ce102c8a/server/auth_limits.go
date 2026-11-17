package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/sordado123/vulnetic/config"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (s *Server) sessionCurrent(w http.ResponseWriter, r *http.Request, claims *vulneticClaims) bool {
	status, message := s.sessionStatus(claims)
	if status != 0 {
		writeErr(w, status, message)
		return false
	}
	return true
}

func (s *Server) sessionStatus(claims *vulneticClaims) (int, string) {
	if claims == nil || claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return 401, "Session is no longer valid"
	}
	if claims.UserID == 0 && !config.SaaSMode() {
		return 0, ""
	}
	if claims.UserID <= 0 || s.m == nil || s.m.pg == nil {
		return 401, "Unauthorized"
	}
	_, hash, err := s.m.pg.UserByID(claims.AccountID, claims.UserID)
	if err != nil {
		return 401, "Session is no longer valid"
	}
	blocked, version, err := s.m.pg.AccountSessionState(claims.AccountID)
	if err != nil {
		return 503, errDataSourceUnavailable
	}
	if blocked || version != claims.AccountVersion || subtle.ConstantTimeCompare([]byte(claims.PasswordVersion), []byte(passwordVersion(hash))) != 1 {
		return 401, "Session is no longer valid"
	}
	return 0, ""
}

func (s *Server) streamSessionContext(ctx context.Context, claims *vulneticClaims, interval time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if status, _ := s.sessionStatus(claims); status != 0 {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

func passwordVersion(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])
}

type authWindow struct {
	start time.Time
	count int
}
type authLimiter struct {
	mu      sync.Mutex
	windows map[string]authWindow
}

func (l *authLimiter) allow(key string, limit int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = make(map[string]authWindow)
	}
	for k, window := range l.windows {
		if now.Sub(window.start) >= time.Minute {
			delete(l.windows, k)
		}
	}
	window, exists := l.windows[key]
	if !exists {
		if len(l.windows) >= 10000 {
			return false
		}
		window.start = now
	}
	if window.count >= limit {
		return false
	}
	window.count++
	l.windows[key] = window
	return true
}

func (s *Server) allowAuthAttempt(w http.ResponseWriter, r *http.Request, email string) bool {
	// RemoteAddr is authoritative; untrusted forwarded headers cannot bypass limits.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	if !s.authLimits.allow("ip:"+ip, 10, now) || (email != "" && !s.authLimits.allow("email:"+strings.ToLower(strings.TrimSpace(email)), 5, now)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "Too many authentication attempts; retry in one minute")
		return false
	}
	return true
}
