// Package reverseagent carries executor sessions over an outbound connection.
// No inbound SSH service or authorized_keys change is needed on the VPS.
package reverseagent

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type WebSocketConn struct {
	*websocket.Conn
	readMu, writeMu       sync.Mutex
	reader                io.Reader
	deadlineMu            sync.Mutex
	readTimer, writeTimer *time.Timer
	closed                bool
}

func (c *WebSocketConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.reader == nil {
			kind, reader, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *WebSocketConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WebSocketConn) LocalAddr() net.Addr  { return c.UnderlyingConn().LocalAddr() }
func (c *WebSocketConn) RemoteAddr() net.Addr { return c.UnderlyingConn().RemoteAddr() }
func (c *WebSocketConn) Close() error {
	c.deadlineMu.Lock()
	if c.closed {
		c.deadlineMu.Unlock()
		return nil
	}
	c.closed = true
	if c.readTimer != nil {
		c.readTimer.Stop()
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.deadlineMu.Unlock()
	return c.Conn.Close()
}
func (c *WebSocketConn) setTimer(timer **time.Timer, t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if !t.IsZero() {
		*timer = time.AfterFunc(time.Until(t), func() { _ = c.Close() })
	}
	return nil
}
func (c *WebSocketConn) SetReadDeadline(t time.Time) error  { return c.setTimer(&c.readTimer, t) }
func (c *WebSocketConn) SetWriteDeadline(t time.Time) error { return c.setTimer(&c.writeTimer, t) }
func (c *WebSocketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// Each stream is independently owned; closing it leaves sibling executors intact.
type ChannelConn struct {
	ssh.Channel
	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

func (c *ChannelConn) Close() error {
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
	return c.Channel.Close()
}
func (c *ChannelConn) LocalAddr() net.Addr  { return &net.UnixAddr{Name: "executor", Net: "agent"} }
func (c *ChannelConn) RemoteAddr() net.Addr { return &net.UnixAddr{Name: "VPS", Net: "agent"} }
func (c *ChannelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !t.IsZero() {
		c.timer = time.AfterFunc(time.Until(t), func() { _ = c.Close() })
	}
	return nil
}
func (c *ChannelConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *ChannelConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func OpenExecutor(client *ssh.Client) (net.Conn, error) {
	channel, requests, err := client.OpenChannel("vulnetic-executor", nil)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(requests)
	return &ChannelConn{Channel: channel}, nil
}
