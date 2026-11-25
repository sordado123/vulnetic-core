package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/sshexec"
)

type pythonFixtureTransport struct {
	command string
	env     []string
}

func (t *pythonFixtureTransport) Start(_ context.Context, _ string, env []string, command string, out io.Writer) (actool.ExecHandle, error) {
	t.command, t.env = command, append([]string{}, env...)
	_, _ = io.WriteString(out, "fixture completed")
	return pythonFixtureHandle{}, nil
}
func (*pythonFixtureTransport) OpenStdio(context.Context, string, []string) (io.Reader, io.Writer, io.Closer, error) {
	return nil, nil, nil, errors.New("unexpected stdio")
}
func (*pythonFixtureTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected network")
}
func (*pythonFixtureTransport) ActiveSessions() int { return 0 }
func (*pythonFixtureTransport) Close() error        { return nil }

type pythonFixtureHandle struct{}

func (pythonFixtureHandle) Wait() error        { return nil }
func (pythonFixtureHandle) ExitCode(error) int { return 0 }
func (pythonFixtureHandle) Kill()              {}

func TestRemotePythonResolvesScopedInputBeforeEncoding(t *testing.T) {
	transport := &pythonFixtureTransport{}
	ex := sshexec.NewTransportExecutor(transport, "/fixture/workspace")
	const ref = "VULNETIC_CRED_1_PASSWORD"
	const secret = "synthetic-only-password"
	ex.SecretResolver = func(input string) ([]string, error) {
		if strings.Contains(input, ref) {
			return []string{ref + "=" + secret}, nil
		}
		return nil, nil
	}
	tc := &actool.ToolContext{Executor: ex, Env: []string{"FIXTURE=original"}}
	result, err := remotePython(context.Background(), "pass", map[string]any{"env": ref}, 1000, tc)
	if err != nil || result.IsError || transport.command == "" {
		t.Fatalf("remote helper failed: %+v %v", result, err)
	}
	if strings.Contains(transport.command, secret) || !strings.Contains(strings.Join(transport.env, "\n"), ref+"="+secret) {
		t.Fatal("scoped input must travel only in the executor environment")
	}
	if len(tc.Env) != 1 || tc.Env[0] != "FIXTURE=original" {
		t.Fatal("helper mutated the shared tool environment")
	}
}
