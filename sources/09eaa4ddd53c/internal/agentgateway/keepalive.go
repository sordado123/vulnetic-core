package agentgateway

import (
	"context"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"log"
	"time"
)

const executorHeartbeatInterval = 20 * time.Second
const executorHeartbeatTimeout = 5 * time.Second

// The private control heartbeat does not travel through the public executor tunnel.
func keepExecutorAlive(ctx context.Context, client *ssh.Client, correlation string) {
	ticker := time.NewTicker(executorHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			done := make(chan bool, 1)
			go func() { ok, _, err := client.SendRequest("keepalive@vulnetic", true, nil); done <- ok && err == nil }()
			timer := time.NewTimer(executorHeartbeatTimeout)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case ok := <-done:
				timer.Stop()
				if ok {
					continue
				}
				log.Printf("[gateway] event=executor_heartbeat_failed connection=%s", correlation)
			case <-timer.C:
				log.Printf("[gateway] event=executor_heartbeat_timeout connection=%s", correlation)
			}
			_ = client.Close()
			return
		}
	}
}

// Session traffic can also be silent while a remote command is still running.
func startSessionHeartbeat(ctx context.Context, ws *websocket.Conn) {
	_ = ws.SetReadDeadline(time.Now().Add(3 * executorHeartbeatInterval))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(3 * executorHeartbeatInterval)) })
	go keepSessionAlive(ctx, ws)
}

func keepSessionAlive(ctx context.Context, ws *websocket.Conn) {
	ticker := time.NewTicker(executorHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(executorHeartbeatTimeout)); err != nil {
				_ = ws.Close()
				return
			}
		}
	}
}
