package sshexec

import (
	"context"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

func (l *LazyExecutor) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if config.SaaSMode() {
		var err error
		address, err = l.protectedAddress(ctx, address)
		if err != nil {
			return nil, err
		}
	}
	if l.transport != nil {
		return l.transport.DialContext(ctx, network, address)
	}
	l.initialize()
	if l.err != nil {
		return nil, l.err
	}
	return l.inner.client.DialContext(ctx, network, address)
}

type remoteStdio struct {
	session      *ssh.Session
	done         chan struct{}
	once         sync.Once
	closeSession func() error
}

func (s *remoteStdio) Close() error {
	var err error
	s.once.Do(func() { close(s.done); err = s.closeSession() })
	return err
}

func (l *LazyExecutor) OpenStdio(ctx context.Context, command string, env []string) (io.Reader, io.Writer, io.Closer, error) {
	if config.SaaSMode() {
		if err := platformpolicy.CheckText(command); err != nil {
			return nil, nil, nil, err
		}
	}
	if l.transport != nil {
		return l.transport.OpenStdio(ctx, command, env)
	}
	l.initialize()
	if l.err != nil {
		return nil, nil, nil, l.err
	}
	session, err := l.inner.newSession()
	if err != nil {
		return nil, nil, nil, err
	}
	closer := &remoteStdio{session: session, done: make(chan struct{}), closeSession: func() error { return l.inner.closeSession(session) }}
	stdin, err := session.StdinPipe()
	if err != nil {
		closer.Close()
		return nil, nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		closer.Close()
		return nil, nil, nil, err
	}
	session.Stderr = io.Discard
	if err = session.Start(l.inner.sessionCommand(l.workDir, env, command)); err != nil {
		closer.Close()
		return nil, nil, nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			closer.Close()
		case <-closer.done:
		}
	}()
	return stdout, stdin, closer, nil
}
