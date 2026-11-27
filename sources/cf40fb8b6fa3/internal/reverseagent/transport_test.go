package reverseagent_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
)

func connection(t *testing.T) (*ssh.Client, func() *ssh.Client, context.CancelFunc, <-chan error) {
	t.Helper()
	host, err := sshexec.GenerateKeypair("agent")
	if err != nil {
		t.Fatal(err)
	}
	client, err := sshexec.GenerateKeypair("platform")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(host.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(client.PublicKeyOpenSSH))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	directory := t.TempDir()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = reverseagent.Serve(ctx, conn, reverseagent.ExecutorConfig{HostKey: signer, ClientKey: key, Username: "fixture", Directory: directory})
		}
		done <- err
	}()
	outer, err := sshexec.DialPinned("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "fixture", client.PrivateKeyPEM, host.PublicKeyOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outer.Close() })
	open := func() *ssh.Client {
		stream, err := reverseagent.OpenExecutor(outer)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := sshexec.DialPinnedConn(stream, "fixture", client.PrivateKeyPEM, host.PublicKeyOpenSSH)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		return inner
	}
	return outer, open, cancel, done
}

func TestBetaAgentTransport(t *testing.T) {
	outer, open, cancel, done := connection(t)
	a, b := open(), open()
	_ = a.Close()
	if ok, _, err := b.SendRequest("keepalive@vulnetic", true, nil); err != nil || !ok {
		t.Fatalf("closing one executor affected its sibling: %v", err)
	}
	stream, err := reverseagent.OpenExecutor(outer)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := sshexec.GenerateKeypair("wrong")
	if err != nil {
		t.Fatal(err)
	}
	if bad, err := sshexec.DialPinnedConn(stream, "fixture", wrong.PrivateKeyPEM, wrong.PublicKeyOpenSSH); err == nil {
		_ = bad.Close()
		t.Fatal("unexpected identity accepted")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "through-agent") }))
	defer target.Close()
	transport := &http.Transport{DialContext: b.DialContext}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "through-agent" {
		t.Fatalf("forwarding: %s %v", body, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("lease cancellation did not close channels")
	}
	if _, _, err := b.SendRequest("keepalive@vulnetic", true, nil); err == nil {
		t.Fatal("executor survived cancellation")
	}
}

func TestAgentExecAndCancellationLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux executor process lifecycle; required by Linux CI")
	}
	_, open, _, _ := connection(t)
	client := open()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.CombinedOutput("printf RUN_OK; printf STDERR_OK >&2; exit 7")
	_ = session.Close()
	var exit *ssh.ExitError
	if !strings.Contains(string(out), "RUN_OK") || !strings.Contains(string(out), "STDERR_OK") {
		t.Fatalf("command output: %s", out)
	}
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
		t.Fatalf("exit status: %v", err)
	}
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.Start("sleep 30 & echo $!; wait"); err != nil {
		t.Fatal(err)
	}
	pid, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err = session.Signal(ssh.SIGKILL); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- session.Wait() }()
	select {
	case err = <-finished:
		if err == nil {
			t.Fatal("cancelled command succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("command survived cancellation")
	}
	_ = session.Close()
	for deadline := time.Now().Add(2 * time.Second); ; {
		stat, err := os.ReadFile("/proc/" + strings.TrimSpace(pid) + "/stat")
		fields := strings.Fields(string(stat))
		if os.IsNotExist(err) || (len(fields) > 2 && fields[2] == "Z") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child process survived cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBetaAgentWebSocketByteStream(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		stream := &reverseagent.WebSocketConn{Conn: ws}
		_, _ = io.Copy(stream, stream)
	}))
	defer server.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := &reverseagent.WebSocketConn{Conn: ws}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	message := strings.Repeat("binary\x00packet\n", 4096)
	for _, part := range []string{message[:10], message[10:]} {
		if _, err = stream.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	buffer := make([]byte, len(message))
	if _, err = io.ReadFull(stream, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != message {
		t.Fatal("WebSocket frame boundaries corrupted the byte stream")
	}
}

func TestBetaAgentURLPolicy(t *testing.T) {
	for _, raw := range []string{"http://example.com", "file:///tmp/agent", "https://user:secret@example.com", "https://example.com/subpath", "https://example.com/?token=example", "http://localhost.evil.invalid"} {
		if _, err := reverseagent.ValidateServerURL(raw); err == nil {
			t.Fatal("unsafe or ambiguous platform URL accepted")
		}
	}
	for _, raw := range []string{"https://example.com", "http://127.0.0.1:8793", "http://[::1]:8793"} {
		if _, err := reverseagent.ValidateServerURL(raw); err != nil {
			t.Fatal(err)
		}
	}
}
