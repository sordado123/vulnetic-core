//go:build windows && windowsagentintegration

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/internal/winsecure"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

var integrationAgent = flag.String("agent-binary", "", "Windows foreground test executable")
var integrationResult = flag.String("agent-results", "", "local synthetic test result")

func TestMain(m *testing.M) {
	flag.Parse()
	var log *os.File
	if *integrationResult != "" {
		var err error
		log, err = os.OpenFile(*integrationResult+".log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			os.Exit(2)
		}
		os.Stdout, os.Stderr = log, log
	}
	code := m.Run()
	if log != nil {
		_ = log.Sync()
		_ = log.Close()
	}
	os.Exit(code)
}

type terminalRun struct {
	command                    *exec.Cmd
	done                       chan error
	output                     bytes.Buffer
	ready                      chan *ssh.Client
	failures                   chan string
	joinCount, connectionCount atomic.Int32
	revoked                    atomic.Bool
	mu                         sync.Mutex
	identity                   reverseagent.EnrollmentRequest
	deadline                   time.Time
	platform                   sshexec.GeneratedKeypair
	workspace, enrollment      string
	clients                    []*ssh.Client
}

func newTerminalRun(t *testing.T, lifetime time.Duration) *terminalRun {
	t.Helper()
	f := &terminalRun{ready: make(chan *ssh.Client, 8), failures: make(chan string, 8), done: make(chan error, 1)}
	var err error
	f.platform, err = sshexec.GenerateKeypair("terminal-loopback-fixture")
	if err != nil {
		t.Fatal(err)
	}
	randomToken := func() string {
		var data [32]byte
		if _, e := rand.Read(data[:]); e != nil {
			t.Fatal(e)
		}
		return base64.RawURLEncoding.EncodeToString(data[:])
	}
	join, runtimeToken := randomToken(), randomToken()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/enroll":
			if r.Header.Get("Authorization") != "Bearer "+join || f.joinCount.Add(1) != 1 {
				http.Error(w, "invalid enrollment", 401)
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&f.identity) != nil || f.identity.Platform != "windows" {
				http.Error(w, "invalid identity", 400)
				return
			}
			f.deadline = time.Now().UTC().Add(lifetime)
			_ = json.NewEncoder(w).Encode(reverseagent.Enrollment{RuntimeToken: runtimeToken, ClientPublicKey: f.platform.PublicKeyOpenSSH, LeaseSeconds: 300, ExpiresAt: f.deadline})
		case "/agent/connect":
			if f.revoked.Load() {
				http.Error(w, "revoked", 410)
				return
			}
			if r.Header.Get("Authorization") != "Bearer "+runtimeToken {
				http.Error(w, "invalid identity", 401)
				return
			}
			ws, e := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if e != nil {
				return
			}
			f.mu.Lock()
			identity := f.identity
			f.mu.Unlock()
			client, e := sshexec.DialPinnedConn(&reverseagent.WebSocketConn{Conn: ws}, identity.Username, f.platform.PrivateKeyPEM, identity.HostKey)
			if e != nil {
				_ = ws.Close()
				f.failures <- "authenticated handshake failed"
				return
			}
			f.mu.Lock()
			f.clients = append(f.clients, client)
			f.mu.Unlock()
			f.connectionCount.Add(1)
			f.ready <- client
			_ = client.Wait()
			_ = client.Close()
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	base := t.TempDir()
	sid, e := winsecure.UserSID()
	if e != nil {
		t.Fatal(e)
	}
	if e = winsecure.Restrict(base, sid, true); e != nil {
		t.Fatal(e)
	}
	f.workspace = filepath.Join(base, "workspace")
	if e = os.Mkdir(f.workspace, 0700); e != nil {
		t.Fatal(e)
	}
	f.enrollment = filepath.Join(base, "enrollment")
	if e = os.WriteFile(f.enrollment, []byte(join), 0600); e != nil {
		t.Fatal(e)
	}
	f.command = exec.Command(*integrationAgent, "-connect", "-server", server.URL, "-enrollment-file", f.enrollment, "-directory", f.workspace, "-lease-seconds", "300")
	f.command.Stdout, f.command.Stderr = &f.output, &f.output
	if e = f.command.Start(); e != nil {
		t.Fatal("foreground process could not start", e)
	}
	go func() { f.done <- f.command.Wait() }()
	t.Cleanup(func() {
		_ = f.command.Process.Kill()
		f.mu.Lock()
		clients := append([]*ssh.Client(nil), f.clients...)
		f.mu.Unlock()
		for _, client := range clients {
			_ = client.Close()
		}
	})
	return f
}

func (f *terminalRun) await(t *testing.T) *ssh.Client {
	t.Helper()
	select {
	case client := <-f.ready:
		return client
	case err := <-f.done:
		t.Fatal("foreground executor exited before connecting", err, f.output.String())
	case failure := <-f.failures:
		t.Fatal(failure)
	case <-time.After(20 * time.Second):
		t.Fatal("foreground executor did not connect")
	}
	return nil
}

func (f *terminalRun) executor(t *testing.T, outer *ssh.Client) *sshexec.LazyExecutor {
	t.Helper()
	stream, err := reverseagent.OpenExecutor(outer)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	identity := f.identity
	f.mu.Unlock()
	inner, err := sshexec.DialPinnedConn(stream, identity.Username, f.platform.PrivateKeyPEM, identity.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	executor := sshexec.NewTaskExecutor(func() (*ssh.Client, error) { return inner, nil }, nil, "task-fixture")
	executor.Platform = "windows"
	t.Cleanup(func() { _ = executor.Close() })
	return executor
}

func terminalSleepingProcess(t *testing.T, executor *sshexec.LazyExecutor) windows.Handle {
	t.Helper()
	read, write := io.Pipe()
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	handle, err := executor.Start(t.Context(), "", nil, `$p=New-Object System.Diagnostics.Process; $p.StartInfo.FileName=(Join-Path $PSHOME 'powershell.exe'); $p.StartInfo.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120'; $p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true; [void]$p.Start(); [Console]::WriteLine($p.Id); Start-Sleep -Seconds 120`, write)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = handle.Wait(); _ = write.Close() }()
	line := make(chan string, 1)
	go func() { s, _ := bufio.NewReader(read).ReadString('\n'); line <- s }()
	var pidLine string
	select {
	case pidLine = <-line:
	case <-time.After(15 * time.Second):
		t.Fatal("command did not report PID")
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(pidLine), 10, 32)
	if err != nil {
		t.Fatal("invalid command PID", pidLine, err)
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(process) })
	return process
}

func assertTerminalCommandStopped(t *testing.T, process windows.Handle) {
	t.Helper()
	state, err := windows.WaitForSingleObject(process, 7000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("terminal shutdown left a command running", state, err)
	}
}

func TestWindowsTerminalLifecycle(t *testing.T) {
	result := map[string]any{"passed": false, "production_untouched": true, "phase": "starting"}
	t.Cleanup(func() {
		result["passed"] = !t.Failed()
		if *integrationResult != "" {
			data, _ := json.MarshalIndent(result, "", "  ")
			if err := os.WriteFile(*integrationResult, data, 0600); err != nil {
				t.Error(err)
			}
		}
	})
	if err := requireWindowsTerminalUser(); err != nil {
		t.Fatal("mandatory foreground test requires a non-administrator token", err)
	}
	if *integrationAgent == "" || *integrationResult == "" {
		t.Fatal("explicit artifact and result paths are required")
	}
	data, err := os.ReadFile(*integrationAgent)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	result["agent_sha256"] = hex.EncodeToString(sum[:])
	t.Run("reconnect-and-expire", func(t *testing.T) {
		result["phase"] = "reconnect-and-expire"
		f := newTerminalRun(t, 22*time.Second)
		outer := f.await(t)
		ex := f.executor(t, outer)
		if _, e := os.Stat(f.enrollment); !os.IsNotExist(e) {
			t.Fatal("enrollment input was retained", e)
		}
		var out bytes.Buffer
		command := `$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 1}; [Console]::Write('NONADMIN_OK')`
		h, e := ex.Start(t.Context(), "", nil, command, &out)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.Wait(); e != nil || out.String() != "NONADMIN_OK" {
			t.Fatal("command was not non-administrator", out.String(), e)
		}
		proof := []byte("synthetic retained evidence")
		path, e := ex.RestoreUpload(t.Context(), "proof.txt", proof)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ex.RestoreUpload(t.Context(), "proof.txt", proof); e != nil {
			t.Fatal("idempotent restore", e)
		}
		read, write, closer, e := ex.OpenStdio(t.Context(), `while (($line=[Console]::ReadLine()) -ne $null) { [Console]::WriteLine($line) }`, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(write, "terminal-stdio\n"); e != nil {
			t.Fatal(e)
		}
		echo, e := bufio.NewReader(read).ReadString('\n')
		if e != nil || strings.TrimSpace(echo) != "terminal-stdio" {
			t.Fatal("stdio failed", echo, e)
		}
		_ = closer.Close()
		f.mu.Lock()
		before := f.deadline
		hostKey := f.identity.HostKey
		f.mu.Unlock()
		_ = ex.Close()
		_ = outer.Close()
		outer = f.await(t)
		ex = f.executor(t, outer)
		f.mu.Lock()
		same := before.Equal(f.deadline) && hostKey == f.identity.HostKey
		f.mu.Unlock()
		if !same || f.joinCount.Load() != 1 || f.connectionCount.Load() < 2 {
			t.Fatal("reconnect changed identity or authorization")
		}
		process := terminalSleepingProcess(t, ex)
		select {
		case e = <-f.done:
			if e != nil {
				t.Fatal("expiration did not finish cleanly", e, f.output.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatal("executor did not expire")
		}
		assertTerminalCommandStopped(t, process)
		if !strings.Contains(f.output.String(), before.UTC().Format(time.RFC3339)) {
			t.Fatal("original deadline not disclosed")
		}
		if saved, e := os.ReadFile(filepath.FromSlash(path)); e != nil || !bytes.Equal(saved, proof) {
			t.Fatal("expiration removed workspace evidence", e)
		}
		result["reconnect_original_deadline"] = true
		result["non_administrator"] = true
		result["stdio_restore"] = true
		result["natural_expiration"] = true
	})
	if t.Failed() {
		return
	}
	t.Run("revoke", func(t *testing.T) {
		result["phase"] = "revoke"
		f := newTerminalRun(t, time.Minute)
		outer := f.await(t)
		ex := f.executor(t, outer)
		process := terminalSleepingProcess(t, ex)
		f.revoked.Store(true)
		_ = outer.Close()
		select {
		case e := <-f.done:
			if e != nil {
				t.Fatal("revocation failed", e)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("revoked executor kept running")
		}
		assertTerminalCommandStopped(t, process)
		if f.joinCount.Load() != 1 {
			t.Fatal("revocation obtained a new enrollment")
		}
		result["revocation"] = true
	})
	if t.Failed() {
		return
	}
	t.Run("process-close", func(t *testing.T) {
		result["phase"] = "process-close"
		f := newTerminalRun(t, time.Minute)
		ex := f.executor(t, f.await(t))
		process := terminalSleepingProcess(t, ex)
		if e := f.command.Process.Kill(); e != nil {
			t.Fatal(e)
		}
		select {
		case <-f.done:
		case <-time.After(10 * time.Second):
			t.Fatal("terminated executor kept running")
		}
		assertTerminalCommandStopped(t, process)
		result["abrupt_close_stops_commands"] = true
	})
	result["phase"] = "complete"
}
