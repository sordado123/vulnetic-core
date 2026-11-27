package sshexec

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/admission"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/runstate"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
	"time"
)

type admittedConn struct {
	net.Conn
	release func()
}

func (c *admittedConn) Close() error { err := c.Conn.Close(); c.release(); return err }
func (l *LazyExecutor) DialContext(ctx context.Context, network, address string) (result net.Conn, retErr error) {
	start := time.Now()
	defer func() { runstate.RecordStage(ctx, "connect", start, retErr != nil) }()
	release, err := admission.Connections.Try(l.AccountID)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	wrap := func(c net.Conn, e error) (net.Conn, error) {
		if e != nil {
			return nil, e
		}
		retained = true
		return &admittedConn{c, release}, nil
	}

	addresses := []string{address}
	if config.SaaSMode() {
		var err error
		addresses, err = l.protectedAddresses(ctx, address)
		if err != nil {
			return nil, err
		}
	}
	if l.transport == nil {
		l.initialize()
		if l.err != nil {
			return nil, l.err
		}
	}
	for _, destination := range addresses {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		var connection net.Conn
		if l.transport != nil {
			connection, err = l.transport.DialContext(ctx, network, destination)
		} else {
			connection, err = l.inner.client.DialContext(ctx, network, destination)
		}
		if err == nil {
			return wrap(connection, nil)
		}
		var channel *ssh.OpenChannelError
		if !errors.Is(err, ErrDestinationUnreachable) && !(errors.As(err, &channel) && channel.Reason == ssh.ConnectionFailed) {
			return nil, err
		}
	}
	return nil, err
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

type admittedCloser struct {
	io.Closer
	release func()
	once    sync.Once
	done    chan struct{}
}

func (c *admittedCloser) Close() error {
	var err error
	c.once.Do(func() { close(c.done); err = c.Closer.Close(); c.release() })
	return err
}

func (l *LazyExecutor) OpenStdio(ctx context.Context, command string, env []string) (io.Reader, io.Writer, io.Closer, error) {
	var envErr error
	env, envErr = l.commandEnvironment(command, env)
	if envErr != nil {
		return nil, nil, nil, envErr
	}
	release, err := admission.Connections.Try(l.AccountID)
	if err != nil {
		return nil, nil, nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	wrap := func(rd io.Reader, wr io.Writer, c io.Closer, e error) (io.Reader, io.Writer, io.Closer, error) {
		if e != nil {
			return nil, nil, nil, e
		}
		retained = true
		wrapped := &admittedCloser{Closer: c, release: release, done: make(chan struct{})}
		go func() {
			select {
			case <-ctx.Done():
				wrapped.Close()
			case <-wrapped.done:
			}
		}()
		return rd, wr, wrapped, nil
	}

	if config.SaaSMode() {
		if err := platformpolicy.CheckText(command); err != nil {
			return nil, nil, nil, err
		}
	}
	if l.transport != nil {
		return wrap(l.transport.OpenStdio(ctx, command, env))
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
	return wrap(stdout, stdin, closer, nil)
}
