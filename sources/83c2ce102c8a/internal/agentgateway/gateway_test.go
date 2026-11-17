package agentgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
)

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for gateway state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func TestGatewayRoutesAndCredentials(t *testing.T) {
	g, err := New(strings.Repeat("g", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.Handler{g.PublicHandler(), g.PrivateHandler()} {
		for _, path := range []string{"/api/health", "/api/settings", "/v1/unknown"} {
			r := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("unexpected route available: %s", path)
			}
		}
	}
	r := httptest.NewRequest("GET", "/v1/control", nil)
	r.Header.Set("Authorization", "Bearer account-jwt")
	w := httptest.NewRecorder()
	g.PrivateHandler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("tenant credential accepted on gateway control")
	}
	w = httptest.NewRecorder()
	g.PublicHandler().ServeHTTP(w, httptest.NewRequest("POST", "/agent/enroll", nil))
	if w.Code != 503 {
		t.Fatal("gateway did not fail closed without core")
	}
}
func TestGatewayControlProtocolFailClosed(t *testing.T) {
	token := strings.Repeat("c", 32)
	g, _ := New(token)
	host := httptest.NewServer(g.PrivateHandler())
	defer host.Close()
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(host.URL, "http")+"/v1/control", header)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err = ws.WriteJSON(Message{Version: Version, Type: "execute_on_core", ID: ID()}); err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = ws.ReadMessage(); err == nil {
		t.Fatal("unsolicited operation accepted")
	}
	waitFor(t, func() bool { return g.current() == nil })
	ws, _, err = websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(host.URL, "http")+"/v1/control", header)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(6 * time.Second))
	started := time.Now()
	_, _, err = ws.ReadMessage()
	if err == nil || time.Since(started) > 6*time.Second {
		t.Fatal("missing heartbeat did not close the channel")
	}
}
func gatewayFixture(t *testing.T) (*Client, *Remote, context.CancelFunc, *Gateway) {
	t.Helper()
	token := strings.Repeat("p", 32)
	g, _ := New(token)
	private := httptest.NewServer(g.PrivateHandler())
	public := httptest.NewServer(g.PublicHandler())
	t.Cleanup(private.Close)
	t.Cleanup(public.Close)
	client, err := NewClient(private.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sshexec.GenerateKeypair("fixture")
	if err != nil {
		t.Fatal(err)
	}
	join := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	runtimeToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	runtimeHash := sha256.Sum256([]byte(runtimeToken))
	expires := time.Now().Add(time.Minute)
	ref := ID()
	var mu sync.Mutex
	hostKey := ""
	used := false
	connected := false
	controlCtx, stopControl := context.WithCancel(t.Context())
	t.Cleanup(stopControl)
	go client.Run(controlCtx, func(ctx context.Context, m Message) Message {
		mu.Lock()
		defer mu.Unlock()
		switch m.Type {
		case "enroll":
			if used || m.Request == nil {
				return Message{Error: "already used"}
			}
			used = true
			hostKey = m.Request.HostKey
			return Message{Enrollment: &reverseagent.Enrollment{RuntimeToken: runtimeToken, ClientPublicKey: key.PublicKeyOpenSSH, ExpiresAt: expires, LeaseSeconds: 300}}
		case "authenticate":
			if !bytes.Equal(m.Hash, runtimeHash[:]) {
				return Message{Error: "invalid"}
			}
			return Message{Identity: &Identity{Ref: ref, Username: "fixture", HostKey: hostKey, PrivateKey: key.PrivateKeyPEM, ExpiresAt: expires}}
		case "connected":
			connected = true
			return Message{}
		case "validate":
			if m.Ref != ref {
				return Message{Error: "wrong ref"}
			}
			return Message{}
		case "disconnected":
			connected = false
			return Message{}
		}
		return Message{Error: "unsupported"}
	}, nil)
	waitFor(t, client.Ready)
	agentCtx, stopAgent := context.WithCancel(t.Context())
	t.Cleanup(stopAgent)
	go func() {
		_ = reverseagent.Run(agentCtx, reverseagent.ClientConfig{ServerURL: public.URL, EnrollmentToken: join, Username: "fixture", Directory: t.TempDir()})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return connected })
	return client, client.Remote(ref, "task-workspace"), stopControl, g
}
func TestGatewayAgentConnectionAndControlLoss(t *testing.T) {
	_, remote, stop, g := gatewayFixture(t)
	g.mu.Lock()
	entry := g.agents[remote.ref]
	g.mu.Unlock()
	if entry == nil {
		t.Fatal("agent did not authenticate")
	}
	expires := entry.identity.ExpiresAt
	stop()
	waitFor(t, func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.agents) == 0 })
	if _, err := remote.open(t.Context(), Open{Kind: "exec", Command: "true"}); err == nil {
		t.Fatal("operation allowed after control disconnect")
	}
	if entry.identity.ExpiresAt != expires {
		t.Fatal("control loss renewed expiry")
	}
}
func TestGatewayRemoteExecutionLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux shell fixture; required in the local Linux matrix")
	}
	_, remote, _, _ := gatewayFixture(t)
	ex := sshexec.NewTransportExecutor(remote, "task-workspace")
	defer ex.Close()
	var out bytes.Buffer
	h, err := ex.Start(t.Context(), "", nil, "printf hello; printf error >&2; exit 7", &out)
	if err != nil {
		t.Fatal(err)
	}
	err = h.Wait()
	if err == nil || h.ExitCode(err) != 7 || !strings.Contains(out.String(), "hello") || !strings.Contains(out.String(), "error") {
		t.Fatalf("exit/output contract failed: %d %q %v", h.ExitCode(err), out.String(), err)
	}
	r, w, closer, err := ex.OpenStdio(t.Context(), "cat", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, "stdio-payload"); err != nil {
		t.Fatal(err)
	}
	if err = w.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	_ = closer.Close()
	if err != nil || string(data) != "stdio-payload" {
		t.Fatalf("stdio failed: %q %v", data, err)
	}
	if _, err = ex.RestoreUpload(t.Context(), "proof.txt", []byte("immutable-proof")); err != nil {
		t.Fatal("restore failed", err)
	}
	if _, err = ex.RestoreUpload(t.Context(), "proof.txt", []byte("immutable-proof")); err != nil {
		t.Fatal("idempotent restore failed", err)
	}
	if _, err = ex.RestoreUpload(t.Context(), "proof.txt", []byte("changed")); err == nil {
		t.Fatal("conflicting restore overwrote proof")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	h, err = ex.Start(ctx, "", nil, "sleep 30", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = h.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("remote cancellation did not stop the command")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			defer conn.Close()
			_, _ = fmt.Fprint(conn, "remote-tcp")
		}
	}()
	conn, err := ex.DialContext(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, err = io.ReadAll(conn)
	if err != nil || string(data) != "remote-tcp" {
		t.Fatalf("TCP forwarding failed: %q %v", data, err)
	}
}
