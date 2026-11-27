package reverseagent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/internal/reverseagent"
)

func TestBetaAgentRequiresTrustedTLS(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(401) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := reverseagent.Run(ctx, reverseagent.ClientConfig{ServerURL: server.URL, EnrollmentToken: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Username: "fixture"})
	if err == nil || received.Load() != 0 {
		t.Fatal("enrollment credentials sent to an untrusted TLS endpoint")
	}
}

func TestBetaAgentLeaseDurationBoundaries(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, seconds := range []int{299, 10800, 86400, 259200, 604800, 604801} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			var connections atomic.Int64
			host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/agent/connect" {
					connections.Add(1)
					w.WriteHeader(http.StatusGone)
					return
				}
				_ = json.NewEncoder(w).Encode(reverseagent.Enrollment{RuntimeToken: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ClientPublicKey: string(ssh.MarshalAuthorizedKey(key)), LeaseSeconds: seconds, ExpiresAt: time.Now().Add(time.Duration(seconds) * time.Second)})
			}))
			defer host.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := reverseagent.Run(ctx, reverseagent.ClientConfig{ServerURL: host.URL, EnrollmentToken: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Username: "fixture", HTTPClient: host.Client()})
			invalid := seconds < 300 || seconds > 604800
			if invalid && (connections.Load() != 0 || err == nil || !strings.Contains(err.Error(), "invalid lease duration")) {
				t.Fatalf("invalid duration reached connection: %v", err)
			}
			if !invalid && (connections.Load() != 1 || err == nil || !strings.Contains(err.Error(), "expired or was revoked")) {
				t.Fatalf("valid lease was rejected before connecting: %v", err)
			}
		})
	}
}
