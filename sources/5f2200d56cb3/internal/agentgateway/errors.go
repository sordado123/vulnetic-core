package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/internal/admission"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
	"net"
)

var (
	ErrGatewayUnavailable = errors.New("gateway_unavailable: executor control channel is unavailable")
	ErrExecutorOffline    = errors.New("executor_offline: the authorized executor has not reconnected")
	ErrExecutorClosed     = errors.New("executor_closed: this execution connection was closed")
	ErrExecutorExpired    = errors.New("executor_expired: the original access deadline has passed")
	ErrExecutorRevoked    = errors.New("executor_revoked: executor authorization is no longer valid")
)

// Only fixed categories cross the gateway; raw errors can contain secrets or URLs.
func operationErrorCode(err error) string {
	if errors.Is(err, platformpolicy.ErrProtectedTarget) {
		return "destination_protected"
	}
	if errors.Is(err, platformpolicy.ErrUnavailable) {
		return "policy_unavailable"
	}
	if errors.Is(err, admission.ErrBusy) {
		return "capacity_busy"
	}
	if errors.Is(err, context.Canceled) {
		return "operation_cancelled"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "operation_timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "remote_dns_failed"
	}
	var channel *ssh.OpenChannelError
	if errors.As(err, &channel) {
		switch channel.Reason {
		case ssh.ConnectionFailed:
			return "remote_connect_failed"
		case ssh.Prohibited:
			return "remote_forward_denied"
		case ssh.ResourceShortage:
			return "capacity_busy"
		case ssh.UnknownChannelType:
			return "remote_protocol_unsupported"
		}
	}
	return "remote_operation_failed"
}

func openingError(code, operation string) error {
	switch code {
	case "executor_expired":
		return ErrExecutorExpired
	case "executor_offline":
		return ErrExecutorOffline
	case "gateway_unavailable":
		return ErrGatewayUnavailable
	}
	messages := map[string]string{
		"destination_protected":       "destination denied by mandatory platform policy",
		"destination_invalid":         "destination address is invalid",
		"policy_unavailable":          "mandatory execution policy is unavailable",
		"capacity_busy":               "executor connection capacity is in use",
		"operation_cancelled":         "remote operation was cancelled",
		"operation_timeout":           "remote operation timed out",
		"remote_dns_failed":           "the remote resolver failed",
		"remote_connect_failed":       "the customer executor could not connect to the destination",
		"remote_forward_denied":       "the customer executor rejected TCP forwarding",
		"remote_protocol_unsupported": "the executor does not support the requested channel",
		"remote_operation_failed":     "the remote operation failed before it could start",
		"remote start failed":         "the remote command could not start (legacy gateway)",
		"remote stream unavailable":   "the remote stream could not open (legacy gateway)",
	}
	message, ok := messages[code]
	if !ok {
		return fmt.Errorf("executor_protocol_error: invalid gateway acknowledgement for %s", operation)
	}
	diagnostic := fmt.Sprintf("executor_operation_failed: operation=%s category=%s: %s", operation, code, message)
	if code == "remote_connect_failed" {
		return fmt.Errorf("%s: %w", diagnostic, sshexec.ErrDestinationUnreachable)
	}
	return errors.New(diagnostic)
}
