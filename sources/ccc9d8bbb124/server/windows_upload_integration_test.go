//go:build windows && windowsagentintegration

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"github.com/sordado123/vulnetic/internal/winsecure"
	"github.com/sordado123/vulnetic/sshexec"
	"golang.org/x/sys/windows"
)

// Opt-in: starts only a loopback platform and the exact supplied foreground executor.
func TestWindowsExecutorUploadIntegration(t *testing.T) {
	// TestMain appends _server to the explicitly supplied disposable database.
	fixture, err := url.Parse(os.Getenv("VULNETIC_PG_DSN"))
	if err != nil || fixture.Hostname() != "127.0.0.1" || fixture.Path != "/uploadfixture_server" || os.Getenv("VULNETIC_REQUIRE_PG_TESTS") != "true" {
		t.Fatal("explicit disposable loopback PostgreSQL database uploadfixture is required")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("integration must run without administrator privileges")
	}
	binary := os.Getenv("VULNETIC_WINDOWS_UPLOAD_AGENT")
	blob, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("provide the packaged Windows executor", err)
	}
	digest := sha256.Sum256(blob)
	if hex.EncodeToString(digest[:]) != os.Getenv("VULNETIC_WINDOWS_UPLOAD_SHA256") {
		t.Fatal("executor checksum mismatch")
	}
	t.Setenv("VULNETIC_SAAS_MODE", "false")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	operator := m.pg
	t.Cleanup(func() { _ = operator.Close() })
	appDSN, err := config.PostgresAppDSN()
	if err != nil || appDSN == "" {
		t.Fatal("RLS is required", err)
	}
	m.pg, err = db.OpenRuntime(appDSN)
	if err != nil {
		t.Fatal(err)
	}
	m.assets = m.pg.Assets()
	t.Cleanup(func() { _ = m.Close() })
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	gateway, err := agentgateway.New(strings.Repeat("local-upload-fixture-", 3))
	if err != nil {
		t.Fatal(err)
	}
	private := httptest.NewServer(gateway.PrivateHandler())
	t.Cleanup(private.Close)
	public := httptest.NewServer(gateway.PublicHandler())
	t.Cleanup(public.Close)
	tokenPath := filepath.Join(t.TempDir(), "gateway-token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("local-upload-fixture-", 3)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNETIC_GATEWAY_URL", private.URL)
	t.Setenv("VULNETIC_GATEWAY_TOKEN_FILE", tokenPath)
	t.Setenv("VULNETIC_AGENT_PUBLIC_URL", public.URL)
	state := t.TempDir()
	s := New(ctx, m, state, state, state)
	host := httptest.NewServer(s.Handler())
	t.Cleanup(host.Close)
	account, user, err := m.pg.CreateAccountWithAdmin("Windows upload fixture", "windows-upload@fixture.invalid", "fixture", s.seedAccountCatalog)
	if err != nil {
		t.Fatal(err)
	}
	other, otherUser, err := m.pg.CreateAccountWithAdmin("Foreign fixture", "foreign-upload@fixture.invalid", "fixture", s.seedAccountCatalog)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signJWTForPassword(s.jwtKey, account.ID, user.ID, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := signJWTForPassword(s.jwtKey, other.ID, otherUser.ID, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, auth, contentType string, body io.Reader, want int) []byte {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, host.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Content-Type", contentType)
		response, err := (&http.Client{Timeout: 45 * time.Second}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, response.StatusCode, want, data)
		}
		return data
	}
	var enrollment struct {
		Target  db.SSHTarget `json:"target"`
		Command string       `json:"command"`
	}
	raw := request("POST", "/api/execution-agents", token, "application/json", strings.NewReader(`{"name":"Windows loopback upload","platform":"windows","lease_seconds":300}`), 200)
	if json.Unmarshal(raw, &enrollment) != nil {
		t.Fatal("invalid enrollment response")
	}
	join := regexp.MustCompile(`WriteAllText\(\$enrollment,'([^']+)'`).FindStringSubmatch(enrollment.Command)
	if len(join) != 2 {
		t.Fatal("missing foreground enrollment input")
	}
	clientRoot := t.TempDir()
	sid, err := winsecure.UserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := winsecure.Restrict(clientRoot, sid, true); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(clientRoot, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	joinPath := filepath.Join(clientRoot, "enrollment")
	if err := os.WriteFile(joinPath, []byte(join[1]), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-connect", "-server", public.URL, "-enrollment-file", joinPath, "-directory", workspace, "-lease-seconds", "300")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() { _ = command.Process.Kill(); cancel() })
	ready := func() *db.SSHTarget {
		t.Helper()
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			if target, err := s.verifiedTarget(account.ID, enrollment.Target.ID); err == nil {
				return target
			}
			select {
			case err := <-done:
				t.Fatal("executor exited", err, output.String())
			default:
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("Windows executor did not pass real preflight")
		return nil
	}
	original := ready()
	task, err := m.CreateTaskWithOptions("Windows attachments", "fixture only", db.TaskCreateOptions{AccountID: account.ID, UserID: user.ID, SSHTargetID: &enrollment.Target.ID})
	if err != nil {
		t.Fatal(err)
	}
	filesPath := "/api/tasks/" + task.ID + "/files"
	upload := func(path, auth, name string, data []byte, status int) []byte {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		part, err := form.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		return request("POST", path, auth, form.FormDataContentType(), &body, status)
	}
	key, err := sshexec.GenerateKeypair("synthetic-upload-only")
	if err != nil {
		t.Fatal(err)
	}
	var uploaded struct {
		Files []taskFile `json:"files"`
	}
	if json.Unmarshal(upload(filesPath, token, "fixture key", key.PrivateKeyPEM, 201), &uploaded) != nil || len(uploaded.Files) != 1 {
		t.Fatal("missing uploaded key")
	}
	f := uploaded.Files[0]
	data, err := os.ReadFile(filepath.FromSlash(f.RemotePath))
	if err != nil || !bytes.Equal(data, key.PrivateKeyPEM) {
		t.Fatal("executor key bytes differ", err)
	}
	if !strings.HasPrefix(filepath.Clean(filepath.FromSlash(f.RemotePath)), workspace+string(filepath.Separator)) || !strings.Contains(f.RemotePath, "/temp/uploads/") {
		t.Fatal("upload escaped client workspace")
	}
	if _, err := s.readTaskFile(task, f.ID, true); !os.IsNotExist(err) {
		t.Fatal("raw file unexpectedly retained by platform", err)
	}
	request("GET", filesPath+"/"+f.ID, token, "", nil, 404)
	upload(filesPath, foreign, "foreign", []byte("forbidden"), 404)
	meta, err := os.ReadFile(filepath.Join(m.dir, "accounts", fmt.Sprint(account.ID), "task-files", task.ID, f.ID+".vlt"))
	if err != nil || len(meta) > 4096 || bytes.Contains(meta, key.PrivateKeyPEM) {
		t.Fatal("platform stored input content", err)
	}
	ex, closeExecutor, err := s.remoteExecutor(account.ID, enrollment.Target.ID, fmt.Sprintf(".vulnetic/accounts/%d/tasks/%s", account.ID, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer closeExecutor()
	var readback bytes.Buffer
	psPath := "'" + strings.ReplaceAll(f.RemotePath, "'", "''") + "'"
	ps := `$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 1}; & ssh-keygen.exe -y -f ` + psPath + `; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}`
	h, err := ex.Start(t.Context(), "", nil, ps, &readback)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Wait(); err != nil || !strings.Contains(readback.String(), strings.Join(strings.Fields(key.PublicKeyOpenSSH)[:2], " ")) {
		t.Fatal("uploaded key is unusable by the non-admin agent", err, readback.String())
	}
	large := bytes.Repeat([]byte{0x5a}, 20<<20)
	upload(filesPath, token, "twenty-mib.dat", large, 201)
	upload(filesPath, token, "over-limit.dat", append(large, 0x5a), 413)
	conversation, err := m.pg.CreateConversation(account.ID, "mainagent", "Upload fixture", nil, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetConversationExecutor(account.ID, conversation.ID, &enrollment.Target.ID); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct {
		query string
		owner *Task
	}{
		{"scope=task&id=" + task.ID, task},
		{fmt.Sprintf("scope=session&id=conv-%d", conversation.ID), &Task{AccountID: account.ID, ID: fmt.Sprintf("conv-%d", conversation.ID)}},
		{fmt.Sprintf("scope=staging&id=windows-draft&ssh_target_id=%d", enrollment.Target.ID), &Task{AccountID: account.ID, ID: "draft-windows-draft"}},
	} {
		var result struct {
			Attachments []chatAttachment `json:"attachments"`
		}
		if json.Unmarshal(upload("/api/chat/upload?"+scope.query, token, "input.txt", []byte("synthetic input"), 200), &result) != nil || len(result.Attachments) != 1 || !s.validUploadedAttachments(account.ID, &enrollment.Target.ID, result.Attachments) {
			t.Fatal("attachment provenance failed", scope.query)
		}
		if contents, err := os.ReadFile(filepath.FromSlash(result.Attachments[0].Path)); err != nil || string(contents) != "synthetic input" {
			t.Fatal("chat file missing from Windows workspace", err)
		}
	}
	if err := s.promoteTaskDraft(task, "windows-draft"); err != nil {
		t.Fatal(err)
	}
	legacy := taskFile{ID: uuid.NewString(), Name: "old.txt", RemoteName: "old.txt"}
	if err := s.saveTaskFile(task, legacy, []byte("old retained upload")); err != nil {
		t.Fatal(err)
	}
	if string(request("GET", filesPath+"/"+legacy.ID, token, "", nil, 200)) != "old retained upload" {
		t.Fatal("old upload changed")
	}
	s.remoteMu.Lock()
	ref := s.agentConnections[remoteOwner{account.ID, enrollment.Target.ID}].gatewayRef
	s.remoteMu.Unlock()
	s.gateway.Revoke(ref) // Drop only this local transport; the stored authorization is unchanged.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		s.remoteMu.Lock()
		entry := s.agentConnections[remoteOwner{account.ID, enrollment.Target.ID}]
		reconnected := entry != nil && entry.gatewayRef != ref
		s.remoteMu.Unlock()
		if reconnected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	current := ready()
	s.remoteMu.Lock()
	reconnected := s.agentConnections[remoteOwner{account.ID, enrollment.Target.ID}].gatewayRef != ref
	s.remoteMu.Unlock()
	if !reconnected || current.HostKey != original.HostKey || !current.AgentExpiresAt.Equal(*original.AgentExpiresAt) {
		t.Fatal("reconnection changed identity or expiration")
	}
	if _, err := os.Stat(joinPath); !os.IsNotExist(err) {
		t.Fatal("enrollment secret was retained")
	}
	request("POST", fmt.Sprintf("/api/execution-agents/%d/revoke", enrollment.Target.ID), token, "application/json", strings.NewReader(`{}`), 200)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("revocation failed", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("revoked executor remained running")
	}
	if _, err := os.Stat(filepath.FromSlash(f.RemotePath)); err != nil {
		t.Fatal("revocation deleted uploaded data", err)
	}
	t.Log("PASS: packaged non-admin Windows executor, RLS API/gateway, usable SSH key, task/session/draft uploads, 20 MiB boundary, legacy download, reconnect with unchanged identity/deadline, revocation")
}
