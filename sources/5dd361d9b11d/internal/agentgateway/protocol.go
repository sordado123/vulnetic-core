// Package agentgateway terminates untrusted executor protocols away from the SaaS core.
package agentgateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("gateway operation denied")

const Version = 1
const maxFrame = 64 << 10
const controlTimeout = 5 * time.Second

// Message is deliberately not an RPC: only these events can cross into the core.
// Ref is issued by the core. No account or task identity is accepted from the gateway.
type Message struct {
	Version    int                             `json:"version"`
	Type       string                          `json:"type"`
	ID         string                          `json:"id,omitempty"`
	Ref        string                          `json:"ref,omitempty"`
	Hash       []byte                          `json:"hash,omitempty"`
	SourceIP   string                          `json:"source_ip,omitempty"`
	Request    *reverseagent.EnrollmentRequest `json:"request,omitempty"`
	Enrollment *reverseagent.Enrollment        `json:"enrollment,omitempty"`
	Identity   *Identity                       `json:"identity,omitempty"`
	Temporary  bool                            `json:"temporary,omitempty"`
	Error      string                          `json:"error,omitempty"`
}
type Identity struct {
	Ref        string    `json:"ref"`
	Username   string    `json:"username"`
	PrivateKey []byte    `json:"private_key"`
	HostKey    string    `json:"host_key"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type Open struct {
	Ref       string   `json:"ref"`
	Kind      string   `json:"kind"` // exec, stdio or tcp; the core always initiates.
	Directory string   `json:"directory,omitempty"`
	Command   string   `json:"command,omitempty"`
	Env       []string `json:"env,omitempty"`
	Address   string   `json:"address,omitempty"`
}
type Status struct {
	Type  string `json:"type"` // ready or exit
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
func authenticated(r *http.Request, token string) bool {
	return len(token) >= 32 && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(token)) == 1
}

var upgrade = websocket.Upgrader{HandshakeTimeout: 5 * time.Second, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}

type control struct {
	ws        *websocket.Conn
	mu        sync.Mutex
	pendingMu sync.Mutex
	pending   map[string]chan Message
	done      chan struct{}
	once      sync.Once
}

func newControl(ws *websocket.Conn) *control {
	ws.SetReadLimit(maxFrame)
	return &control{ws: ws, pending: make(map[string]chan Message), done: make(chan struct{})}
}
func (c *control) send(m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m.Version = Version
	_ = c.ws.SetWriteDeadline(time.Now().Add(3 * time.Second))
	return c.ws.WriteJSON(m)
}
func (c *control) close() { c.once.Do(func() { close(c.done); _ = c.ws.Close() }) }
func (c *control) request(ctx context.Context, m Message) (Message, error) {
	m.ID = ID()
	ch := make(chan Message, 1)
	c.pendingMu.Lock()
	if len(c.pending) >= 32 {
		c.pendingMu.Unlock()
		return Message{}, errors.New("gateway busy")
	}
	c.pending[m.ID] = ch
	c.pendingMu.Unlock()
	defer func() { c.pendingMu.Lock(); delete(c.pending, m.ID); c.pendingMu.Unlock() }()
	if err := c.send(m); err != nil {
		return Message{}, err
	}
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	select {
	case reply := <-ch:
		if reply.Error != "" {
			if reply.Temporary {
				return Message{}, errors.New("executor control temporarily unavailable")
			}
			return Message{}, fmt.Errorf("%w: %s", ErrDenied, reply.Error)
		}
		return reply, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-c.done:
		return Message{}, io.EOF
	case <-timer.C:
		return Message{}, context.DeadlineExceeded
	}
}
func (c *control) deliver(m Message) bool {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	ch := c.pending[m.ID]
	if ch == nil {
		return false
	}
	select {
	case ch <- m:
		return true
	default:
		return false
	}
}
