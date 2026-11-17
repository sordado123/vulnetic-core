package sshexec

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"io"
	"net"
	"testing"
)

type policyTransport struct {
	answers string
	dialed  string
}

func (t *policyTransport) Start(ctx context.Context, dir string, env []string, command string, out io.Writer) (tool.ExecHandle, error) {
	_, _ = io.WriteString(out, t.answers)
	return policyHandle{}, nil
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

type policyHandle struct{}

func (policyHandle) Wait() error        { return nil }
func (policyHandle) ExitCode(error) int { return 0 }
func (policyHandle) Kill()              {}
func TestManagedRemoteDNSProtectsPlatform(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	t.Setenv("VULNETIC_PUBLIC_URL", "")
	t.Setenv("VULNETIC_AGENT_PUBLIC_URL", "")
	t.Setenv("VULNETIC_PROTECTED_TARGETS", "")
	for _, answer := range []string{`{"addresses":["136.64.138.78"],"names":["alias.example"]}`, `{"addresses":["104.16.1.2"],"names":["vulnetic.site"]}`, `{"addresses":["::ffff:136.64.138.78"],"names":[]}`} {
		transport := &policyTransport{answers: answer}
		ex := NewTransportExecutor(transport, "fixture")
		_, err := ex.DialContext(t.Context(), "tcp", "alias.example:443")
		if !errors.Is(err, platformpolicy.ErrProtectedTarget) || transport.dialed != "" {
			t.Fatalf("DNS alias escaped policy: %v %s", err, transport.dialed)
		}
	}
	transport := &policyTransport{answers: `{"addresses":["192.168.50.10"],"names":["lab.example"]}`}
	ex := NewTransportExecutor(transport, "fixture")
	_, _ = ex.DialContext(t.Context(), "tcp", "lab.example:443")
	if transport.dialed != "192.168.50.10:443" {
		t.Fatal("private address was blocked or the connection was not pinned", transport.dialed)
	}
}
