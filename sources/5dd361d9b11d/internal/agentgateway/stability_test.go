package agentgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

type idleTestListener struct {
	net.Listener
	timeout time.Duration
}

func (l idleTestListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &idleTestConn{Conn: c, timeout: l.timeout}, nil
}

type idleTestConn struct {
	net.Conn
	mu      sync.Mutex
	timer   *time.Timer
	timeout time.Duration
	closed  bool
}

func (c *idleTestConn) touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.timer == nil {
		c.timer = time.AfterFunc(c.timeout, func() { _ = c.Close() })
	} else {
		c.timer.Reset(c.timeout)
	}
}
func (c *idleTestConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		active := c.timer != nil
		c.mu.Unlock()
		if active {
			c.touch()
		}
	}
	return n, e
}
func (c *idleTestConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.mu.Lock()
		active := c.timer != nil
		c.mu.Unlock()
		if active {
			c.touch()
		}
	}
	return n, e
}
func (c *idleTestConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
func gatewayPublicTestServer(handler http.Handler, idle time.Duration) *httptest.Server {
	if idle == 0 {
		return httptest.NewServer(handler)
	}
	s := httptest.NewUnstartedServer(handler)
	s.Listener = idleTestListener{s.Listener, idle}
	s.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			conn.(*idleTestConn).touch()
		}
	}
	s.Start()
	return s
}

func TestGatewayTransientDisconnectKeepsHandleUsable(t *testing.T) {
	_, remote, _, _ := gatewayFixture(t)
	var output bytes.Buffer
	first, err := remote.Start(t.Context(), "", nil, "printf first", &output)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Wait(); err != nil {
		t.Fatal(err)
	}
	remote.Disconnect()
	second, err := remote.Start(t.Context(), "", nil, "printf second", &output)
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "firstsecond" {
		t.Fatal(output.String())
	}
	_ = remote.Close()
	if _, err = remote.Start(t.Context(), "", nil, "printf forbidden", &output); err != ErrExecutorClosed {
		t.Fatalf("closed executor reopened: %v", err)
	}
}
func TestGatewayResolverRunsBeforeEachNewOperation(t *testing.T) {
	client, base, _, _ := gatewayFixture(t)
	calls := 0
	remote := client.ResolvingRemote("fixture", func(context.Context) (string, error) { calls++; return base.ref, nil })
	for range 2 {
		var output bytes.Buffer
		h, e := remote.Start(t.Context(), "", nil, "printf ok", &output)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.Wait(); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 {
		t.Fatal("stale binding reused", calls)
	}
	revoked := client.ResolvingRemote("fixture", func(context.Context) (string, error) { return "", ErrExecutorRevoked })
	if _, e := revoked.open(t.Context(), Open{Kind: "exec", Command: "printf forbidden"}); e != ErrExecutorRevoked {
		t.Fatal("revocation bypassed", e)
	}
}

// This explicit operator soak is excluded from ordinary fast suites, never reported as executed unless enabled.
func TestGatewayStabilityThirtyMinutes(t *testing.T) {
	if os.Getenv("VULNETIC_GATEWAY_SOAK") != "1" {
		t.Skip("operator 30-minute VPS soak requires VULNETIC_GATEWAY_SOAK=1")
	}
	if os.Getuid() == 0 {
		t.Fatal("soak executor must run without root")
	}
	const duration = 30 * time.Minute
	_, idle, _, idleGateway := gatewayFixtureLease(t, duration+10*time.Minute, 120*time.Second)
	_, active, _, activeGateway := gatewayFixtureLease(t, duration+10*time.Minute, 120*time.Second)
	idleGateway.mu.Lock()
	idleEntry := idleGateway.agents[idle.ref]
	idleExpiry := idleEntry.identity.ExpiresAt
	idleGateway.mu.Unlock()
	activeGateway.mu.Lock()
	activeEntry := activeGateway.agents[active.ref]
	activeExpiry := activeEntry.identity.ExpiresAt
	activeGateway.mu.Unlock()
	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), duration+2*time.Minute)
	defer cancel()
	var quiet bytes.Buffer
	quietHandle, e := active.Start(ctx, "", nil, "sleep 1800; printf quiet-complete", &quiet)
	if e != nil {
		t.Fatal(e)
	}
	operations := 0
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	finish := time.NewTimer(duration)
	defer finish.Stop()
	t.Logf("SOAK_STARTED utc=%s uid=%d seconds=%d idle_proxy_seconds=120", started.UTC().Format(time.RFC3339), os.Getuid(), int(duration/time.Second))
loop:
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-finish.C:
			break loop
		case <-tick.C:
			idleGateway.mu.Lock()
			idleSame := idleGateway.agents[idle.ref] == idleEntry
			idleGateway.mu.Unlock()
			activeGateway.mu.Lock()
			activeSame := activeGateway.agents[active.ref] == activeEntry
			activeGateway.mu.Unlock()
			if !idleSame || !activeSame {
				t.Fatalf("connection was replaced: idle=%t active=%t after %v", idleSame, activeSame, time.Since(started))
			}
			operation, stop := context.WithTimeout(ctx, 8*time.Second)
			var result bytes.Buffer
			h, err := active.Start(operation, "", nil, "printf stability-ok", &result)
			if err == nil {
				err = h.Wait()
			}
			stop()
			if err != nil || result.String() != "stability-ok" {
				t.Fatalf("active operation %d: %v", operations, err)
			}
			operations++
			if operations%6 == 0 {
				t.Logf("SOAK_PROGRESS elapsed_seconds=%d active_operations=%d", int(time.Since(started).Seconds()), operations)
			}
		}
	}
	if err := quietHandle.Wait(); err != nil || quiet.String() != "quiet-complete" {
		t.Fatalf("silent active session failed: %v", err)
	}
	if time.Since(started) < duration || operations < 170 {
		t.Fatal("incomplete observation period")
	}
	idleGateway.mu.Lock()
	idleSame := idleGateway.agents[idle.ref] == idleEntry && idleEntry.identity.ExpiresAt.Equal(idleExpiry)
	idleGateway.mu.Unlock()
	activeGateway.mu.Lock()
	activeSame := activeGateway.agents[active.ref] == activeEntry && activeEntry.identity.ExpiresAt.Equal(activeExpiry)
	activeGateway.mu.Unlock()
	if !idleSame || !activeSame {
		t.Fatal("identity or original deadline changed")
	}
	result := map[string]any{"passed": true, "duration_seconds": time.Since(started).Seconds(), "idle_connection_unchanged": true, "active_connection_unchanged": true, "active_operations": operations, "silent_session_seconds": 1800, "original_expiries_preserved": true, "uid": os.Getuid(), "paid_llm_calls": 0, "proxy_idle_timeout_seconds": 120, "production_used": false}
	raw, _ := json.Marshal(result)
	fmt.Printf("SOAK_RESULT=%s\n", raw)
}
