package agentgateway

import (
	"context"
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net"
)

// Log bounded categories, never raw errors that may contain URLs or credentials.
func disconnectReason(err error) string {
	if err == nil {
		return "closed"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, io.EOF) {
		return "peer_eof"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "network_timeout"
	}
	var closed *websocket.CloseError
	if errors.As(err, &closed) {
		switch closed.Code {
		case websocket.CloseNormalClosure:
			return "normal_close"
		case websocket.CloseGoingAway:
			return "peer_going_away"
		case websocket.CloseAbnormalClosure:
			return "abnormal_close"
		}
		return "websocket_close"
	}
	return "transport_error"
}
