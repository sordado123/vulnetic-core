package sshexec

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"io"
	"net"
	"strings"
	"testing"
)

type policyTransport struct {
	answers   string
	responses []string
	starts    int
	waitErr   error
	dialed    string
}

func (t *policyTransport) Start(ctx context.Context, dir string, env []string, command string, out io.Writer) (tool.ExecHandle, error) {
	answer := t.answers
	if t.starts < len(t.responses) {
		answer = t.responses[t.starts]
	}
	t.starts++
	_, _ = io.WriteString(out, answer)
	return policyHandle{err: t.waitErr}, nil
}
func (t *policyTransport) OpenStdio(context.Context, string, []string) (io.Reader, io.Writer, io.Closer, error) {
	return nil, nil, nil, errors.New("unused")
}
func (t *policyTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.dialed = address
	return nil, errors.New("fixture stop")
}
func (t *policyTransport) ActiveSessions() int { return 0 }
func (t *policyTransport) Close() error        { return nil }

type policyHandle struct{ err error }

func (h policyHandle) Wait() error { return h.err }
func (policyHandle) ExitCode(err error) int {
	if err != nil {
		return 127
	}
	return 0
}
func (policyHandle) Kill() {}
func TestManagedRemoteDNSProtectsPlatform(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	t.Setenv("VULNETIC_PUBLIC_URL", "")
	t.Setenv("VULNETIC_AGENT_PUBLIC_URL", "")
	t.Setenv("VULNETIC_PROTECTED_TARGETS", "")
	for _, answer := range []string{`{"addresses":["136.64.138.78"],"names":["alias.example"]}`, `{"addresses":["104.16.1.2"],"names":["vulnetic.site"]}`, `{"addresses":["::ffff:136.64.138.78"],"names":[]}`} {
		transport := &policyTransport{answers: answer}
		ex := NewTransportExecutor(transport, "fixture")
		ex.AccountID = 1
		_, err := ex.DialContext(t.Context(), "tcp", "alias.example:443")
		if !errors.Is(err, platformpolicy.ErrProtectedTarget) || transport.dialed != "" {
			t.Fatalf("DNS alias escaped policy: %v %s", err, transport.dialed)
		}
	}
	transport := &policyTransport{answers: `{"addresses":["192.168.50.10"],"names":["lab.example"]}`}
	ex := NewTransportExecutor(transport, "fixture")
	ex.AccountID = 1
	_, _ = ex.DialContext(t.Context(), "tcp", "lab.example:443")
	if transport.dialed != "192.168.50.10:443" {
		t.Fatal("private address was blocked or the connection was not pinned", transport.dialed)
	}
}

func TestRemoteDNSRetriesOnlyTransientFailures(t *testing.T) {
	transport := &policyTransport{responses: []string{`{"error":"temporary"}`, `{"addresses":["192.168.1.2"],"names":["lab.example"]}`}}
	ex := NewTransportExecutor(transport, "fixture")
	result, err := ex.resolveRemoteDNS(t.Context(), "lab.example")
	if err != nil || transport.starts != 2 || len(result.Addresses) != 1 {
		t.Fatal("transient DNS lookup was not recovered", err, transport.starts)
	}
	transport = &policyTransport{answers: `{"error":"not_found"}`}
	ex = NewTransportExecutor(transport, "fixture")
	_, err = ex.resolveRemoteDNS(t.Context(), "missing.example")
	var dns *net.DNSError
	if !errors.As(err, &dns) || !dns.IsNotFound || transport.starts != 1 || transport.dialed != "" {
		t.Fatal("permanent lookup failure was retried or dialed", err)
	}
}
func TestRemoteDNSRuntimeFailureRemainsVisible(t *testing.T) {
	transport := &policyTransport{waitErr: errors.New("synthetic remote exit 127")}
	ex := NewTransportExecutor(transport, "fixture")
	_, err := ex.resolveRemoteDNS(t.Context(), "lab.example")
	if err == nil || !strings.Contains(err.Error(), "python3 was not found") || transport.dialed != "" {
		t.Fatal("runtime error was disguised as DNS failure", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ex.resolveRemoteDNS(ctx, "lab.example")
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost", err)
	}
}

func TestRemoteDNSWorkspaceFailureIsNotReportedAsNameFailure(t *testing.T) {
	transport := &policyTransport{answers: "mkdir: cannot create directory: Permission denied", waitErr: errors.New("synthetic remote failure")}
	ex := NewTransportExecutor(transport, "fixture")
	_, err := ex.resolveRemoteDNS(t.Context(), "lab.example")
	if err == nil || !strings.Contains(err.Error(), "workspace") || strings.Contains(err.Error(), transport.answers) || transport.dialed != "" {
		t.Fatal("workspace failure was disguised or raw output leaked", err)
	}
}
