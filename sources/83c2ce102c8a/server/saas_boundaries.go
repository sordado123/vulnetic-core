package server

import (
	"net/http"
	"strings"

	"github.com/sordado123/vulnetic/config"
)

// Infrastructure stays in operator configuration, outside customer APIs.
func (s *Server) withSaaSBoundaries(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.SaaSMode() {
			path := r.URL.Path
			if strings.HasPrefix(path, "/api/ssh-targets/") && (strings.HasSuffix(path, "/host-key") || strings.HasSuffix(path, "/install-command")) {
				writeErr(w, 404, "use a temporary execution agent")
				return
			}
			if r.Method != http.MethodGet && (strings.HasPrefix(path, "/api/task-archives") || strings.HasSuffix(path, "/archive") || path == "/api/tasks/archive/batch") {
				writeErr(w, 409, "Cold archives are operator-only during the SaaS beta; task history is preserved")
				return
			}
			for _, prefix := range []string{"/api/settings", "/api/logs", "/api/update", "/api/sync/scopesentry", "/api/traffic"} {
				if path == prefix || strings.HasPrefix(path, prefix+"/") {
					writeErr(w, 404, "resource not found")
					return
				}
			}
			if path == "/api/gc" || path == "/api/llm" || path == "/api/llm/test" {
				writeErr(w, 404, "resource not found")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
