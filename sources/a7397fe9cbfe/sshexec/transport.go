package sshexec

import (
	"context"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"io"
	"net"
)

// Transport lets the SaaS core use a gateway without parsing remote SSH packets.
// Uploads deliberately retain the existing checksum and safe-path implementation.
type Transport interface {
	Start(context.Context, string, []string, string, io.Writer) (tool.ExecHandle, error)
	OpenStdio(context.Context, string, []string) (io.Reader, io.Writer, io.Closer, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	ActiveSessions() int
	Close() error
}

func NewTransportExecutor(t Transport, directory string) *LazyExecutor {
	return &LazyExecutor{transport: t, workDir: directory}
}
