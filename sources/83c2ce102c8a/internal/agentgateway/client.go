package agentgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client only opens outbound connections. A gateway event can never install a tool or execute core code.
type Client struct {
	URL, Token string
	mu         sync.Mutex
	control    *control
	ready      atomic.Bool
}

func NewClient(address, token string) (*Client, error) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(token) < 32 {
		return nil, errors.New("invalid private gateway configuration")
	}
	return &Client{URL: strings.TrimSuffix(address, "/"), Token: token}, nil
}
func (c *Client) endpoint(path string) string {
	u, _ := url.Parse(c.URL + path)
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else {
		u.Scheme = "wss"
	}
	return u.String()
}
func (c *Client) dial(ctx context.Context, path string) (*websocket.Conn, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+c.Token)
	ws, _, err := (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).DialContext(ctx, c.endpoint(path), h)
	return ws, err
}
func (c *Client) Ready() bool { return c != nil && c.ready.Load() }
func (c *Client) Revoke(ref string) {
	c.mu.Lock()
	control := c.control
	c.mu.Unlock()
	if control != nil {
		_ = control.send(Message{Type: "revoke", Ref: ref})
	}
}
func (c *Client) Run(ctx context.Context, handle func(context.Context, Message) Message, disconnected func()) {
	for ctx.Err() == nil {
		c.run(ctx, handle)
		if disconnected != nil {
			disconnected()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
func (c *Client) run(ctx context.Context, handle func(context.Context, Message) Message) {
	ws, err := c.dial(ctx, "/v1/control")
	if err != nil {
		return
	}
	ctrl := newControl(ws)
	c.mu.Lock()
	c.control = ctrl
	c.mu.Unlock()
	c.ready.Store(true)
	session, stop := context.WithCancel(ctx)
	defer stop()
	defer func() {
		c.ready.Store(false)
		ctrl.close()
		c.mu.Lock()
		if c.control == ctrl {
			c.control = nil
		}
		c.mu.Unlock()
	}()
	closeOnCancel := context.AfterFunc(session, ctrl.close)
	defer closeOnCancel()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-session.Done():
				return
			case <-ticker.C:
				if ctrl.send(Message{Type: "heartbeat"}) != nil {
					ctrl.close()
					return
				}
			}
		}
	}()
	slots := make(chan struct{}, 32)
	for {
		_ = ws.SetReadDeadline(time.Now().Add(controlTimeout))
		var message Message
		if ws.ReadJSON(&message) != nil || message.Version != Version {
			return
		}
		if message.Type == "heartbeat" {
			continue
		}
		switch message.Type {
		case "enroll", "authenticate", "connected", "disconnected", "validate":
		default:
			return
		}
		if len(message.ID) != 32 || len(message.Ref) > 64 || len(message.Hash) > 32 || len(message.SourceIP) > 64 {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			return
		}
		go func(m Message) {
			defer func() { <-slots }()
			request, done := context.WithTimeout(session, 3*time.Second)
			defer done()
			reply := handle(request, m)
			reply.Type = "reply"
			reply.ID = m.ID
			if err := ctrl.send(reply); err != nil {
				ctrl.close()
			}
		}(message)
	}
}

type Remote struct {
	client         *Client
	ref, directory string
	mu             sync.Mutex
	closed         bool
	streams        map[*stream]struct{}
}

func (c *Client) Remote(ref, directory string) *Remote {
	return &Remote{client: c, ref: ref, directory: directory, streams: make(map[*stream]struct{})}
}
func (r *Remote) open(ctx context.Context, req Open) (*stream, error) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed || !r.client.Ready() {
		return nil, errors.New("execution_policy_unavailable: gateway disconnected")
	}
	ws, err := r.client.dial(ctx, "/v1/session")
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(maxFrame)
	stopOpening := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stopOpening()
	req.Ref = r.ref
	req.Directory = r.directory
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err = ws.WriteJSON(req); err != nil {
		_ = ws.Close()
		return nil, err
	}
	s := &stream{WebSocketConn: &reverseagent.WebSocketConn{Conn: ws}, code: -1, done: make(chan struct{})}
	_ = ws.SetReadDeadline(time.Now().Add(20 * time.Second))
	// A fast remote program can write before Start returns. Keep that bounded output.
	for {
		kind, data, e := ws.ReadMessage()
		if e != nil {
			_ = s.Close()
			return nil, e
		}
		if kind == websocket.BinaryMessage {
			if len(s.buffer)+len(data) > maxFrame {
				_ = s.Close()
				return nil, errors.New("excessive output before start acknowledgement")
			}
			s.buffer = append(s.buffer, data...)
			continue
		}
		var status Status
		if kind != websocket.TextMessage || json.Unmarshal(data, &status) != nil || status.Type != "ready" || status.Error != "" {
			_ = s.Close()
			return nil, errors.New("remote operation refused")
		}
		break
	}
	_ = ws.SetReadDeadline(time.Time{})

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	s.onClose = func() { r.mu.Lock(); delete(r.streams, s); r.mu.Unlock() }
	r.streams[s] = struct{}{}
	r.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	return s, nil
}
func (r *Remote) Start(ctx context.Context, dir string, env []string, command string, out io.Writer) (tool.ExecHandle, error) {
	s, err := r.open(ctx, Open{Kind: "exec", Command: command, Env: env})
	if err != nil {
		return nil, err
	}
	h := &handle{stream: s, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		defer s.Close()
		_, h.err = io.Copy(out, s)
		if h.err == nil && !s.exited {
			h.err = errors.New("executor disconnected without an exit status")
		}
		if h.err == nil && s.code != 0 {
			h.err = fmt.Errorf("remote exit %d", s.code)
		}
	}()
	return h, nil
}
func (r *Remote) OpenStdio(ctx context.Context, command string, env []string) (io.Reader, io.Writer, io.Closer, error) {
	s, err := r.open(ctx, Open{Kind: "stdio", Command: command, Env: env})
	if err != nil {
		return nil, nil, nil, err
	}
	return s, stdin{s}, s, nil
}
func (r *Remote) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("only TCP forwarding is allowed")
	}
	return r.open(ctx, Open{Kind: "tcp", Address: address})
}
func (r *Remote) ActiveSessions() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.streams) }
func (r *Remote) Close() error {
	r.mu.Lock()
	r.closed = true
	streams := make([]*stream, 0, len(r.streams))
	for s := range r.streams {
		streams = append(streams, s)
	}
	r.mu.Unlock()
	for _, s := range streams {
		_ = s.Close()
	}
	return nil
}

type stream struct {
	*reverseagent.WebSocketConn
	readMu  sync.Mutex
	writeMu sync.Mutex
	buffer  []byte
	code    int
	exited  bool
	once    sync.Once
	done    chan struct{}
	onClose func()
}

func (s *stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.buffer) == 0 {
		if s.exited {
			return 0, io.EOF
		}
		kind, data, err := s.Conn.ReadMessage()
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		switch kind {
		case websocket.BinaryMessage:
			s.buffer = data
		case websocket.TextMessage:
			var status Status
			if json.Unmarshal(data, &status) != nil || status.Type != "exit" || status.Code < -1 || status.Code > 255 {
				return 0, errors.New("invalid gateway response")
			}
			s.code = status.Code
			s.exited = true
		default:
			return 0, errors.New("invalid gateway frame")
		}
	}
	n := copy(p, s.buffer)
	s.buffer = s.buffer[n:]
	return n, nil
}
func (s *stream) Close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.WebSocketConn.Close()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return err
}
func (s *stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		written, err := s.WebSocketConn.Write(p[:n])
		total += written
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

type stdin struct{ *stream }

func (s stdin) Close() error { return s.Conn.WriteMessage(websocket.TextMessage, []byte("eof")) }

type handle struct {
	*stream
	done chan struct{}
	err  error
}

func (h *handle) Wait() error            { <-h.done; return h.err }
func (h *handle) ExitCode(err error) int { <-h.done; return h.code }
func (h *handle) Kill()                  { _ = h.Close() }
