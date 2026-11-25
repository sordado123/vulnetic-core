package sshexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/admission"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/reverseagent"
)

// Executor implements tool.Executor over one cached SSH connection to a
// customer's own VPS (Fase B, Modo A). One Executor is bound to one
// ssh_target for the lifetime of a task run — see server/assembly.go's
// wiring, which resolves it from the task's ssh_target_id.
//
// Env is passed inline in the command text ("export K=V; ...") rather than
// via the SSH protocol's channel-request env mechanism: most sshd configs
// reject arbitrary client-sent env vars unless the name is listed in
// AcceptEnv, which a customer's stock VPS will not have set for
// HTTP_PROXY/SSL_CERT_FILE etc.
//
// WorkingDir is applied remotely before environment exports and commands.
type Executor struct {
	client *ssh.Client

	mu       sync.Mutex
	closed   bool
	sessions map[*ssh.Session]struct{}

	// Traffic capture (set by EnableTrafficCapture; zero value = disabled,
	// extraEnv passes through to wrapCommand unchanged).
	tunnelListener net.Listener
	tunnelPort     int
	caRemotePath   string
	// captureFailed is true when EnableTrafficCapture was attempted and
	// failed (most commonly: the VPS's sshd has AllowTcpForwarding no, a
	// common hardened default — see the package doc). Start then strips the
	// proxy/CA env entries instead of leaving in whatever local-shaped
	// values the caller computed: those point at the Vulnetic server's own
	// loopback and are simply unreachable from the remote host, so passing
	// them through would make every HTTP-aware tool call fail its proxy
	// connection instead of just running uncaptured. Remote execution itself
	// still works — only the evidence capture for this target is degraded.
	captureFailed bool
}

// NewExecutor wraps an already-dialed connection (see Dial). The caller owns
// closing it (Close) once the task run that needed it is done.
func NewExecutor(client *ssh.Client) *Executor {
	return &Executor{client: client}
}

// Close closes the underlying SSH connection (and, if traffic capture was
// enabled, the reverse tunnel listener — its relayLoop then exits on the
// next failed Accept). Safe to call once execution is done; any handle
// still in flight will see its session fail.
func (e *Executor) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	sessions := e.sessions
	e.sessions = nil
	e.mu.Unlock()
	for session := range sessions {
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
	}
	if e.tunnelListener != nil {
		_ = e.tunnelListener.Close()
	}
	return e.client.Close()
}

func (e *Executor) newSession() (*ssh.Session, error) {
	session, err := e.client.NewSession()
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		_ = session.Close()
		return nil, fmt.Errorf("SSH executor was revoked")
	}
	if e.sessions == nil {
		e.sessions = make(map[*ssh.Session]struct{})
	}
	e.sessions[session] = struct{}{}
	return session, nil
}

func (e *Executor) closeSession(session *ssh.Session) error {
	_ = session.Signal(ssh.SIGKILL)
	err := session.Close()
	e.releaseSession(session)
	return err
}

func (e *Executor) releaseSession(session *ssh.Session) {
	e.mu.Lock()
	delete(e.sessions, session)
	e.mu.Unlock()
}

// remoteCAPath is where EnableTrafficCapture writes the capture proxy's CA
// certificate on the remote host, inside the SSH user's own home directory
// (no elevated access assumed or needed).
const remoteCAPath = ".vulnetic/ca.pem"

// EnableTrafficCapture requests a reverse port forward (the SSH protocol's
// "-R": the remote sshd opens a listening socket and tunnels connections on
// it back to us) and relays every connection arriving on it to
// localProxyAddr — the Vulnetic server's own capture proxy, reachable from
// this process but not from the customer's VPS directly. It also uploads
// caCertPEM (skip if empty: capture is off) to remoteCAPath so remote HTTPS
// clients can trust the MITM's re-signed certs. Call once per Executor,
// before the first command that should be captured; every subsequent Start
// rewrites HTTP_PROXY/HTTPS_PROXY/CA-trust env entries to point at the
// tunnel instead of whatever local-shaped values the caller passed in (see
// rewriteEnvForTunnel — those values were computed for a local subprocess,
// meaningless on the remote host).
func (e *Executor) EnableTrafficCapture(localProxyAddr string, caCertPEM []byte) error {
	listener, err := e.client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("sshexec: request reverse tunnel: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return fmt.Errorf("sshexec: reverse tunnel address is not TCP: %v", listener.Addr())
	}
	if len(caCertPEM) > 0 {
		if err := e.uploadCACert(caCertPEM); err != nil {
			_ = listener.Close()
			return err
		}
		e.caRemotePath = remoteCAPath
	}
	e.tunnelListener = listener
	e.tunnelPort = tcpAddr.Port
	go e.relayLoop(listener, localProxyAddr)
	return nil
}

func (e *Executor) relayLoop(listener net.Listener, localProxyAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return // listener closed (Executor.Close, or the SSH connection dropped)
		}
		go relayConn(conn, localProxyAddr)
	}
}

// relayConn pipes one tunneled connection to the local capture proxy and
// back, byte for byte — this is a plain TCP relay; the capture proxy itself
// (not this code) is what understands HTTP/HTTPS.
func relayConn(remoteConn net.Conn, localProxyAddr string) {
	defer remoteConn.Close()
	localConn, err := net.Dial("tcp", localProxyAddr)
	if err != nil {
		return
	}
	defer localConn.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(localConn, remoteConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(remoteConn, localConn); done <- struct{}{} }()
	<-done
}

// uploadCACert writes pem to remoteCAPath via a one-shot session piping it
// over stdin — no SFTP subsystem assumed, just a shell and cat.
func (e *Executor) uploadCACert(pem []byte) error {
	session, err := e.newSession()
	if err != nil {
		return fmt.Errorf("sshexec: new session for CA upload: %w", err)
	}
	defer e.closeSession(session)
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("sshexec: CA upload stdin: %w", err)
	}
	if err := session.Start("mkdir -p \"$(dirname " + remoteCAPath + ")\" && cat > " + remoteCAPath); err != nil {
		return fmt.Errorf("sshexec: start CA upload: %w", err)
	}
	if _, err := stdin.Write(pem); err != nil {
		return fmt.Errorf("sshexec: write CA upload: %w", err)
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("sshexec: CA upload failed: %w", err)
	}
	return nil
}

// proxyEnvKeys and caEnvKeys are the env entries rewriteEnvForTunnel
// replaces when traffic capture is on — the exact set agent/worker.go's
// proxyEnv() sets for the local case (see its doc comment), so a remote run
// gets the same effective behavior through the tunnel instead.
var (
	proxyEnvKeys = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"}
	caEnvKeys    = []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS"}
)

// dropProxyEnv removes any proxy/CA entries extraEnv already carries —
// computed for a local subprocess, so the address and cert path are both
// meaningless on the remote host regardless of why they're being dropped.
func dropProxyEnv(extraEnv []string) []string {
	drop := make(map[string]bool, len(proxyEnvKeys)+len(caEnvKeys))
	for _, k := range proxyEnvKeys {
		drop[k] = true
	}
	for _, k := range caEnvKeys {
		drop[k] = true
	}
	out := make([]string, 0, len(extraEnv))
	for _, kv := range extraEnv {
		key, _, _ := strings.Cut(kv, "=")
		if drop[key] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// stripProxyEnv is used when traffic capture was attempted and failed
// (captureFailed) — the command just runs with no proxy/CA env at all,
// rather than one pointing nowhere.
func stripProxyEnv(extraEnv []string) []string {
	return dropProxyEnv(extraEnv)
}

// rewriteEnvForTunnel drops any proxy/CA entries extraEnv already carries
// and substitutes ones pointing at this Executor's own tunnel/uploaded CA.
func (e *Executor) rewriteEnvForTunnel(extraEnv []string) []string {
	out := dropProxyEnv(extraEnv)
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", e.tunnelPort)
	for _, k := range proxyEnvKeys {
		out = append(out, k+"="+proxyURL)
	}
	if e.caRemotePath != "" {
		for _, k := range caEnvKeys {
			out = append(out, k+"="+e.caRemotePath)
		}
	}
	return out
}

// Start assigns Stdout/Stderr via StdoutPipe/StderrPipe and drains them with
// its own io.Copy goroutines, joined by a WaitGroup before Wait returns —
// deliberately NOT the simpler session.Stdout = out / session.Stderr = out
// assignment. golang.org/x/crypto/ssh's Session.Wait() can return as soon as
// the remote side reports exit-status, which is not guaranteed to happen
// only after every data message on the channel has already been delivered
// to the library's own internal copy goroutine for that io.Writer — found
// live: ~10% of runs against a real OpenSSH server returned a nil error
// with zero bytes captured, intermittently, for a command whose output
// absolutely was sent. Draining the pipes ourselves and waiting on our own
// WaitGroup removes that race: Wait cannot return before out has received
// everything the copy goroutines read.
func (e *Executor) Start(ctx context.Context, dir string, extraEnv []string, command string, out io.Writer) (tool.ExecHandle, error) {
	session, err := e.newSession()
	if err != nil {
		return nil, fmt.Errorf("sshexec: new session: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = e.closeSession(session)
		return nil, fmt.Errorf("sshexec: stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = e.closeSession(session)
		return nil, fmt.Errorf("sshexec: stderr pipe: %w", err)
	}

	switch {
	case e.tunnelPort != 0:
		extraEnv = e.rewriteEnvForTunnel(extraEnv)
	case e.captureFailed:
		extraEnv = stripProxyEnv(extraEnv)
	}
	if err := session.Start(e.sessionCommand(dir, extraEnv, command)); err != nil {
		_ = e.closeSession(session)
		return nil, fmt.Errorf("sshexec: start: %w", err)
	}

	// out is very often a plain *bytes.Buffer (ToolContext/Manager's output
	// store), which is not safe for concurrent writers — found live: the
	// stdout and stderr copy goroutines below both target it, and even with
	// stderr completely empty, racing a zero-length Write against stdout's
	// real one corrupted the buffer often enough (~2-14% of runs against a
	// real OpenSSH server, across otherwise-identical sequential sessions)
	// to lose the entire captured output with no error. syncWriter
	// serializes both goroutines' Write calls onto the one real writer.
	sw := &syncWriter{w: out}
	if config.SaaSMode() {
		sw.limit = 1 << 20
	}
	var copyWG sync.WaitGroup
	copyWG.Add(2)
	go func() {
		defer copyWG.Done()
		if _, err := io.Copy(sw, stdout); err != nil {
			_ = e.closeSession(session)
		}
	}()
	go func() {
		defer copyWG.Done()
		if _, err := io.Copy(sw, stderr); err != nil {
			_ = e.closeSession(session)
		}
	}()

	h := &execHandle{session: session, copyWG: &copyWG, stopWatch: make(chan struct{}), outputError: sw.Err, release: func() { e.releaseSession(session) }}
	go h.watchCtx(ctx)
	return h, nil
}

// syncWriter serializes concurrent Write calls onto a single underlying
// io.Writer that may not be safe for concurrent use on its own (*bytes.Buffer
// is the common case here).
type syncWriter struct {
	mu      sync.Mutex
	w       io.Writer
	limit   int64
	written int64
	err     error
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if s.limit > 0 && int64(len(p)) > s.limit-s.written {
		s.err = fmt.Errorf("remote command output exceeded the 1 MiB limit; command interrupted")
		return 0, s.err
	}
	n, err := s.w.Write(p)
	s.written += int64(n)
	if err != nil {
		s.err = err
	}
	return n, err
}

func (s *syncWriter) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.err }

// wrapCommand embeds extraEnv assignments ahead of command as plain shell
// text (see Executor's doc comment for why, not SSH-protocol env). Each
// value is single-quoted to survive a space/special character; the
// assignment itself ("export KEY=") is never attacker-controlled — it
// always comes from ToolContext.Env, built by this codebase, not agent
// output.
func wrapCommand(extraEnv []string, command string) string {
	if len(extraEnv) == 0 {
		return command
	}
	var b strings.Builder
	for _, kv := range extraEnv {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		b.WriteString("export ")
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(shellSingleQuote(value))
		b.WriteString("; ")
	}
	b.WriteString(command)
	return b.String()
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (e *Executor) sessionCommand(dir string, env []string, command string) string {
	if !strings.Contains(string(e.client.ServerVersion()), "Vulnetic-Windows") {
		return commandInDir(dir, env, command)
	}
	spec := reverseagent.NativeCommand{Kind: "exec", Command: command}
	if native, err := reverseagent.DecodeNative(command); err == nil && native.Kind != "exec" {
		spec = native
	}
	spec.Directory = dir
	spec.Env = env
	return reverseagent.EncodeNative(spec)
}

type execHandle struct {
	session     *ssh.Session
	copyWG      *sync.WaitGroup
	stopWatch   chan struct{}
	outputError func() error
	release     func()
}

func (h *execHandle) Wait() error {
	if h.release != nil {
		defer h.release()
	}
	// Drain stdout/stderr to EOF BEFORE calling session.Wait(), not after —
	// reversed, Wait() can tear the channel down as soon as it has the
	// exit-status, racing with (and sometimes winning against) our own
	// in-flight Read()s on the same channel's data. Waiting for the pipes'
	// natural EOF first means every byte the remote sent is already in out
	// by the time we ask for the exit status.
	h.copyWG.Wait()
	err := h.session.Wait()
	// Every prior completed session on this connection was never explicitly
	// closed on the happy path (only Kill did) — found live, across many
	// sequential sessions on one cached connection, that leaving them open
	// correlated with later sessions intermittently returning a clean exit
	// with zero captured output. Close releases the local side regardless
	// of what actually caused that; the remote side is already done once
	// Wait returns.
	_ = h.session.Close()
	close(h.stopWatch)
	if h.outputError != nil {
		return errors.Join(err, h.outputError())
	}
	return err
}

func (h *execHandle) ExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	if h.outputError != nil && h.outputError() != nil {
		return -1
	}
	var exitErr *ssh.ExitError
	if ok := asExitError(waitErr, &exitErr); ok {
		return exitErr.ExitStatus()
	}
	return -1
}

func (h *execHandle) Kill() {
	_ = h.session.Signal(ssh.SIGKILL)
	_ = h.session.Close()
}

// watchCtx kills the remote command if ctx is cancelled (task timeout/abort)
// before the command finishes on its own.
func (h *execHandle) watchCtx(ctx context.Context) {
	select {
	case <-ctx.Done():
		h.Kill()
	case <-h.stopWatch:
	}
}

func asExitError(err error, target **ssh.ExitError) bool { return errors.As(err, target) }

// LazyExecutor defers dialing until the first actual Bash call, not when the
// task's agent bundle is built (server/task_llm.go's agentsForTask runs on
// every turn, most of which never touch Bash — dialing eagerly there would
// cost a network round trip per turn for nothing). A dial failure is
// remembered and returned from every Start call as a normal tool error — it
// does not panic or otherwise abort the agent run; the agent sees "ssh
// target unreachable: ..." exactly like it would see any other failed
// command, and can report or retry.
type LazyExecutor struct {
	// TargetID is assigned by the host before this executor is shared.
	TargetID  int64
	AccountID int64
	Platform  string
	transport Transport
	stateMu   sync.RWMutex
	workDir   string
	dial      func() (*ssh.Client, error)
	// SecretResolver supplies requested task secrets through safely encoded remote environment entries.
	SecretResolver func(string) ([]string, error)
	// enableCapture, when non-nil, is called once right after the first
	// successful dial (before any command runs) to turn on traffic capture
	// for the connection — see Executor.EnableTrafficCapture. A failure here
	// degrades to uncaptured execution (logged, Executor.captureFailed set)
	// rather than failing the whole LazyExecutor: the most common cause is
	// the VPS's sshd having AllowTcpForwarding disabled — a connectivity
	// property unrelated to whether the account can run commands there at
	// all, so losing evidence capture should not also lose remote execution.
	enableCapture func(*Executor) error

	once  sync.Once
	inner *Executor
	err   error
}

func (l *LazyExecutor) ExecutionTargetID() int64 { return l.TargetID }
func (l *LazyExecutor) ExecutionOS() string {
	if l.Platform == "windows" {
		return "windows"
	}
	return "linux"
}

func (l *LazyExecutor) Quote(value string) string {
	if l.ExecutionOS() == "windows" {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return shellSingleQuote(value)
}

// NewLazyExecutor wraps a dial function (typically decrypting the target's
// key and calling Dial) that runs at most once, on first use. enableCapture
// is optional (nil = traffic capture off for this executor).
func NewLazyExecutor(dial func() (*ssh.Client, error), enableCapture func(*Executor) error) *LazyExecutor {
	return &LazyExecutor{dial: dial, enableCapture: enableCapture}
}

type admittedHandle struct {
	tool.ExecHandle
	done chan struct{}
	err  error
}

func (h *admittedHandle) Wait() error { <-h.done; return h.err }
func (l *LazyExecutor) Start(ctx context.Context, dir string, extraEnv []string, command string, out io.Writer) (tool.ExecHandle, error) {
	if config.SaaSMode() {
		if err := platformpolicy.CheckText(command); err != nil {
			return nil, err
		}
	}
	var envErr error
	extraEnv, envErr = l.commandEnvironment(command, extraEnv)
	if envErr != nil {
		return nil, envErr
	}
	release, err := admission.Commands.Try(l.AccountID)
	if err != nil {
		return nil, err
	}
	var handle tool.ExecHandle
	if l.transport != nil {
		handle, err = l.transport.Start(ctx, l.workDir, extraEnv, command, out)
	} else {
		if l.workDir != "" {
			dir = l.workDir
		}
		l.initialize()
		if l.err != nil {
			release()
			return nil, l.err
		}
		handle, err = l.inner.Start(ctx, dir, extraEnv, command, out)
	}
	if err != nil {
		release()
		return nil, err
	}
	h := &admittedHandle{ExecHandle: handle, done: make(chan struct{})}
	go func() { h.err = handle.Wait(); release(); close(h.done) }()
	return h, nil
}

func (l *LazyExecutor) initialize() {
	l.once.Do(func() {
		client, err := l.dial()
		if err != nil {
			l.err = fmt.Errorf("ssh target unreachable: %w", err)
			return
		}
		ex := NewExecutor(client)
		if l.enableCapture != nil {
			if err := l.enableCapture(ex); err != nil {
				ex.captureFailed = true
				log.Printf("[sshexec] traffic capture unavailable, running uncaptured: %v", err)
			}
		}
		l.stateMu.Lock()
		l.inner = ex
		l.stateMu.Unlock()
	})
}

func (l *LazyExecutor) ActiveSessions() int {
	if l != nil && l.transport != nil {
		return l.transport.ActiveSessions()
	}
	if l == nil {
		return 0
	}
	l.stateMu.RLock()
	inner := l.inner
	l.stateMu.RUnlock()
	if inner == nil {
		return 0
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	return len(inner.sessions)
}

// Disconnect drains uncertain streams without granting permission to restart them.
func (l *LazyExecutor) Disconnect() {
	if transport, ok := l.transport.(interface{ Disconnect() }); ok {
		transport.Disconnect()
	} else {
		_ = l.Close()
	}
}

// Close closes the underlying connection, if one was ever actually dialed.
func (l *LazyExecutor) Close() error {
	if l.transport != nil {
		return l.transport.Close()
	}
	l.once.Do(func() { l.err = fmt.Errorf("SSH executor was revoked") })
	if l.inner != nil {
		return l.inner.Close()
	}
	return nil
}

// NewTaskExecutor fixes the remote working directory before the executor is shared.
func NewTaskExecutor(dial func() (*ssh.Client, error), capture func(*Executor) error, dir string) *LazyExecutor {
	l := NewLazyExecutor(dial, capture)
	l.workDir = dir
	return l
}
func commandInDir(dir string, env []string, command string) string {
	if dir == "" {
		return wrapCommand(env, command)
	}
	prefix, check := "", ""
	if strings.HasPrefix(dir, ".vulnetic/accounts/") {
		// An administrative SSH connection must never create a managed customer workspace.
		prefix = "[ \"$(/usr/bin/id -u)\" -ne 0 ] || { printf '%s\\n' 'Permission denied: managed workspace requires a non-root user' >&2; exit 1; }; umask 077; "
		check = " && { [ -O " + shellSingleQuote(dir) + " ] && [ -w " + shellSingleQuote(dir) + " ] && [ -x " + shellSingleQuote(dir) + " ]; } || { printf '%s\\n' 'Permission denied: managed workspace must be owned and writable by the agent user' >&2; exit 1; }"
	}
	return prefix + "mkdir -p -- " + shellSingleQuote(dir) + check + " && cd -- " + shellSingleQuote(dir) + " && (\n" + wrapCommand(env, command) + "\n)"
}
