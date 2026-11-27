package server

import (
	"context"
	"github.com/sordado123/vulnetic/config"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

func (s *Server) withPlatformIngress(next http.Handler) http.Handler {
	var proxies []netip.Prefix
	for _, item := range strings.Split(os.Getenv("VULNETIC_INGRESS_TRUSTED_PROXIES"), ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			panic("invalid trusted ingress proxy")
		}
		proxies = append(proxies, prefix)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.SaaSMode() {
			// These headers previously came from Caddy; retain them when using the tunnel.
			w.Header().Set("Strict-Transport-Security", "max-age=86400")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}

		if !config.SaaSMode() || len(proxies) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid origin", 400)
			return
		}
		ip, err := netip.ParseAddr(peer)
		if err != nil {
			http.Error(w, "invalid origin", 400)
			return
		}
		trusted := false
		for _, prefix := range proxies {
			if prefix.Contains(ip.Unmap()) {
				trusted = true
				break
			}
		}
		if !trusted {
			http.Error(w, "untrusted origin", 403)
			return
		}
		source, err := netip.ParseAddr(r.Header.Get("CF-Connecting-IP"))
		if err != nil {
			http.Error(w, "missing client identity", 403)
			return
		}
		// Only the exact legacy agent routes bypass the site ban. Their own credentials remain mandatory.
		path := r.URL.Path
		agentRoute := (r.Method == "POST" && path == "/agent/enroll") || (r.Method == "GET" && (path == "/agent/connect" || path == "/agent/install.sh" || path == "/agent/binary/amd64" || path == "/agent/binary/arm64" || path == "/agent/checksum/amd64" || path == "/agent/checksum/arm64"))
		if !agentRoute {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			blocked, e := s.m.pg.ExecutorOriginBlocked(ctx, source.Unmap().String())
			cancel()
			if e != nil {
				writeErr(w, 503, "execution_policy_unavailable")
				return
			}
			if blocked {
				// Shared NAT must not lock out an authenticated operator; IP is not a process identity.
				claims, valid := verifyJWT(extractToken(r), s.jwtKey)
				if !valid {
					writeErr(w, 403, "policy_denied: a current authenticated session is required from this executor network")
					return
				}
				if !s.sessionCurrent(w, r, claims) {
					return
				}
			}
		}
		// Downstream authentication limits and audits must use the verified client, not the shared tunnel IP.
		forwarded := r.Clone(r.Context())
		forwarded.RemoteAddr = net.JoinHostPort(source.Unmap().String(), "0")
		next.ServeHTTP(w, forwarded)
	})
}
