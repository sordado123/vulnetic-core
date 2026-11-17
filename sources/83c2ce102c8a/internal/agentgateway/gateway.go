package agentgateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/agentassets"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
)

type connection struct {
	identity Identity
	client   *ssh.Client
}
type attemptBucket struct {
	minute int64
	count  int
}
type Gateway struct {
	LegacyHost     string
	LegacyUntil    time.Time
	limits         map[string]attemptBucket
	Token          string
	TrustedProxies []netip.Prefix
	mu             sync.Mutex
	control        *control
	agents         map[string]*connection
	openings       chan struct{}
	sessions       chan struct{}
}

func New(token string) (*Gateway, error) {
	if len(token) < 32 {
		return nil, errors.New("gateway control token must contain at least 32 bytes")
	}
	return &Gateway{Token: token, agents: make(map[string]*connection), limits: make(map[string]attemptBucket), openings: make(chan struct{}, 16), sessions: make(chan struct{}, 64)}, nil
}
func (g *Gateway) PublicHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /agent/enroll", g.enroll)
	m.HandleFunc("GET /agent/install.sh", agentassets.Installer)
	m.HandleFunc("GET /agent/binary/{arch}", agentassets.Binary)
	m.HandleFunc("GET /agent/checksum/{arch}", agentassets.Checksum)
	m.HandleFunc("GET /agent/connect", g.connect)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		host := r.Host
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		if strings.EqualFold(host, g.LegacyHost) && g.LegacyHost != "" && !time.Now().Before(g.LegacyUntil) {
			http.Error(w, "legacy agent endpoint expired; reinstall using the current command", 410)
			return
		}
		m.ServeHTTP(w, r)
	})
}
func (g *Gateway) PrivateHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/control", g.serveControl)
	m.HandleFunc("GET /v1/session", g.session)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authenticated(r, g.Token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		m.ServeHTTP(w, r)
	})
}
func (g *Gateway) current() *control { g.mu.Lock(); defer g.mu.Unlock(); return g.control }
func (g *Gateway) serveControl(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := newControl(ws)
	g.mu.Lock()
	if g.control != nil {
		g.mu.Unlock()
		c.close()
		return
	}
	g.control = c
	g.mu.Unlock()
	defer func() {
		c.close()
		g.mu.Lock()
		g.control = nil
		for ref, entry := range g.agents {
			_ = entry.client.Close()
			delete(g.agents, ref)
		}
		g.mu.Unlock()
	}()
	for {
		_ = ws.SetReadDeadline(time.Now().Add(controlTimeout))
		var m Message
		if ws.ReadJSON(&m) != nil || m.Version != Version {
			return
		}
		switch m.Type {
		case "heartbeat":
			if c.send(Message{Type: "heartbeat"}) != nil {
				return
			}
		case "reply":
			if !c.deliver(m) {
				return
			}
		case "revoke":
			g.mu.Lock()
			entry := g.agents[m.Ref]
			delete(g.agents, m.Ref)
			g.mu.Unlock()
			if entry != nil {
				_ = entry.client.Close()
			}
		default:
			return
		}
	}
}
func (g *Gateway) source(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}
	ip = ip.Unmap()
	for _, prefix := range g.TrustedProxies {
		if prefix.Contains(ip) {
			source, e := netip.ParseAddr(r.Header.Get("CF-Connecting-IP"))
			if e != nil {
				return "", errors.New("trusted proxy did not provide a client IP")
			}
			return source.Unmap().String(), nil
		}
	}
	return ip.String(), nil
}
func (g *Gateway) publicRequest(w http.ResponseWriter, r *http.Request) (*control, []byte, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	source, err := g.source(r)
	if err != nil {
		http.Error(w, "invalid origin", 400)
		return nil, nil, "", false
	}
	minute := time.Now().Unix() / 60
	g.mu.Lock()
	bucket := g.limits[source]
	if bucket.minute != minute {
		bucket = attemptBucket{minute: minute}
	}
	if len(g.limits) >= 4096 {
		for key, value := range g.limits {
			if value.minute != minute {
				delete(g.limits, key)
			}
		}
	}
	limited := bucket.count >= 60 || (len(g.limits) >= 4096 && bucket.count == 0)
	if !limited {
		bucket.count++
		g.limits[source] = bucket
	}
	g.mu.Unlock()
	if limited {
		http.Error(w, "too many connection attempts", 429)
		return nil, nil, "", false
	}
	c := g.current()
	if c == nil {
		http.Error(w, "executor control unavailable", 503)
		return nil, nil, "", false
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "invalid credential", 401)
		return nil, nil, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(bearer(r))
	if err != nil || len(raw) != 32 {
		http.Error(w, "invalid credential", 401)
		return nil, nil, "", false
	}
	hash := sha256.Sum256([]byte(bearer(r)))
	return c, hash[:], source, true
}

var username = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)

func (g *Gateway) enroll(w http.ResponseWriter, r *http.Request) {
	select {
	case g.openings <- struct{}{}:
		defer func() { <-g.openings }()
	default:
		http.Error(w, "busy", 429)
		return
	}

	c, hash, source, ok := g.publicRequest(w, r)
	if !ok {
		return
	}
	var req reverseagent.EnrollmentRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if json.NewDecoder(r.Body).Decode(&req) != nil || !username.MatchString(req.Username) {
		http.Error(w, "invalid identity", 400)
		return
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(req.HostKey))
	if err != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		http.Error(w, "invalid identity", 400)
		return
	}
	req.HostKey = string(ssh.MarshalAuthorizedKey(key))
	reply, err := c.request(r.Context(), Message{Type: "enroll", Hash: hash, SourceIP: source, Request: &req})
	if err != nil || reply.Enrollment == nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrDenied) {
			status = http.StatusUnauthorized
		}
		http.Error(w, "enrollment unavailable, expired or already used", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply.Enrollment)
}
func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	c, hash, source, ok := g.publicRequest(w, r)
	if !ok {
		return
	}
	select {
	case g.openings <- struct{}{}:
		defer func() { <-g.openings }()
	default:
		http.Error(w, "busy", 429)
		return
	}
	reply, err := c.request(r.Context(), Message{Type: "authenticate", Hash: hash, SourceIP: source})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrDenied) {
			status = http.StatusUnauthorized
		}
		http.Error(w, "agent access unavailable, expired or revoked", status)
		return
	}
	if reply.Identity == nil {
		http.Error(w, "executor control unavailable", 503)
		return
	}
	if !time.Now().Before(reply.Identity.ExpiresAt) {
		http.Error(w, "agent lease ended", 410)
		return
	}
	identity := *reply.Identity
	ws, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(2 << 20)
	outer := &reverseagent.WebSocketConn{Conn: ws}
	defer outer.Close()
	client, err := sshexec.DialPinnedConn(outer, identity.Username, identity.PrivateKey, identity.HostKey)
	if err != nil {
		return
	}
	defer client.Close()
	entry := &connection{identity: identity, client: client}
	g.mu.Lock()
	if g.control != c || g.agents[identity.Ref] != nil || len(g.agents) >= 15 {
		g.mu.Unlock()
		return
	}
	g.agents[identity.Ref] = entry
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.agents, identity.Ref)
		g.mu.Unlock()
		_, _ = c.request(context.Background(), Message{Type: "disconnected", Ref: identity.Ref})
	}()
	if _, err = c.request(r.Context(), Message{Type: "connected", Ref: identity.Ref, SourceIP: source}); err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), identity.ExpiresAt)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.done:
				_ = client.Close()
				return
			case <-ticker.C:
				if _, err := c.request(ctx, Message{Type: "validate", Ref: identity.Ref}); err != nil {
					_ = client.Close()
					return
				}
			}
		}
	}()
	_ = client.Wait()
}
func (g *Gateway) session(w http.ResponseWriter, r *http.Request) {
	select {
	case g.sessions <- struct{}{}:
		defer func() { <-g.sessions }()
	default:
		http.Error(w, "busy", 429)
		return
	}
	ws, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(maxFrame)
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var req Open
	if ws.ReadJSON(&req) != nil || len(req.Command) > 32<<10 || len(req.Env) > 64 || len(req.Directory) > 4096 {
		return
	}
	_ = ws.SetReadDeadline(time.Time{})
	g.mu.Lock()
	entry := g.agents[req.Ref]
	controlReady := g.control != nil
	g.mu.Unlock()
	if !controlReady || entry == nil || !time.Now().Before(entry.identity.ExpiresAt) {
		_ = ws.WriteJSON(Status{Type: "ready", Error: "executor disconnected or expired"})
		return
	}
	stream, err := reverseagent.OpenExecutor(entry.client)
	if err != nil {
		return
	}
	client, err := sshexec.DialPinnedConn(stream, entry.identity.Username, entry.identity.PrivateKey, entry.identity.HostKey)
	if err != nil {
		return
	}
	ex := sshexec.NewTaskExecutor(func() (*ssh.Client, error) { return client, nil }, nil, req.Directory)
	defer ex.Close()
	ctx, cancel := context.WithDeadline(r.Context(), entry.identity.ExpiresAt)
	defer cancel()
	writer := &frameWriter{ws: ws, limit: 32 << 20, started: make(chan struct{})}
	switch req.Kind {
	case "exec":
		writer.limit = 1 << 20
		h, e := ex.Start(ctx, "", req.Env, req.Command, writer)
		if e != nil {
			_ = writer.status(Status{Type: "ready", Error: "remote start failed"})
			return
		}
		defer h.Kill()
		if writer.status(Status{Type: "ready"}) != nil {
			return
		}
		go func() {
			defer cancel()
			for {
				if _, _, e := ws.ReadMessage(); e != nil {
					return
				}
			}
		}()
		e = h.Wait()
		_ = writer.status(Status{Type: "exit", Code: h.ExitCode(e)})
	case "stdio", "tcp":
		var input io.Reader
		var output io.Writer
		var closer io.Closer
		if req.Kind == "stdio" {
			input, output, closer, err = ex.OpenStdio(ctx, req.Command, req.Env)
		} else {
			host, _, e := net.SplitHostPort(req.Address)
			if e != nil || platformpolicy.CheckHost(host) != nil {
				err = errors.New("protected or invalid destination")
			} else {
				var conn net.Conn
				conn, err = ex.DialContext(ctx, "tcp", req.Address)
				if err == nil {
					input, output, closer = conn, conn, conn
				}
			}
		}
		if err != nil {
			_ = writer.status(Status{Type: "ready", Error: "remote stream unavailable"})
			return
		}
		defer closer.Close()
		if writer.status(Status{Type: "ready"}) != nil {
			return
		}
		stop := context.AfterFunc(ctx, func() { _ = closer.Close(); _ = ws.Close() })
		defer stop()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(writer, input)
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			_ = ws.Close()
		}()
		received := 0
		for {
			kind, data, e := ws.ReadMessage()
			received += len(data)
			if received > 32<<20 {
				return
			}
			if e != nil {
				return
			}
			switch kind {
			case websocket.BinaryMessage:
				if _, e = output.Write(data); e != nil {
					return
				}
			case websocket.TextMessage:
				if string(data) != "eof" {
					return
				}
				if c, ok := output.(io.Closer); ok {
					_ = c.Close()
				}
				<-done
				return
			default:
				return
			}
		}
	default:
		_ = writer.status(Status{Type: "ready", Error: "unsupported operation"})
	}
}

type frameWriter struct {
	started   chan struct{}
	startOnce sync.Once
	limit     int
	written   int
	mu        sync.Mutex
	ws        *websocket.Conn
}

func (w *frameWriter) Write(p []byte) (int, error) {
	if w.started != nil {
		<-w.started
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit > 0 && w.written+len(p) > w.limit {
		return 0, errors.New("remote command output exceeded the 1 MiB limit")
	}
	w.written += len(p)
	total := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		_ = w.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := w.ws.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}
func (w *frameWriter) status(s Status) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := w.ws.WriteJSON(s)
	if s.Type == "ready" && w.started != nil {
		w.startOnce.Do(func() { close(w.started) })
	}
	return err
}
