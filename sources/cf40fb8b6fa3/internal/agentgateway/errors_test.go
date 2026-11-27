package agentgateway

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"testing"
)

func TestOpeningFailureCategories(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{platformpolicy.ErrProtectedTarget, "destination_protected"},
		{context.DeadlineExceeded, "operation_timeout"},
		{&net.DNSError{Err: "fixture-secret", Name: "private.invalid"}, "remote_dns_failed"},
		{&ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: "fixture-secret"}, "remote_connect_failed"},
		{&ssh.OpenChannelError{Reason: ssh.Prohibited, Message: "fixture-secret"}, "remote_forward_denied"},
		{errors.New("fixture-secret"), "remote_operation_failed"},
	} {
		code := operationErrorCode(tc.err)
		if code != tc.code {
			t.Fatalf("wrong category %s", code)
		}
		message := openingError(code, "tcp").Error()
		if !strings.Contains(message, tc.code) || strings.Contains(message, "fixture-secret") || strings.Contains(message, "private.invalid") {
			t.Fatal("unsafe or unclassified diagnostic", message)
		}
	}
	if !errors.Is(openingError("executor_expired", "tcp"), ErrExecutorExpired) {
		t.Fatal("expiry identity lost")
	}
	if strings.Contains(openingError("untrusted-secret", "tcp").Error(), "untrusted-secret") {
		t.Fatal("untrusted gateway error leaked")
	}
}
