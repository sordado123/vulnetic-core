package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"github.com/sordado123/vulnetic/internal/reverseagent"
	"github.com/sordado123/vulnetic/sshexec"
)

func TestBetaAgentAPILifecycle(t *testing.T)    { testAgentAPILifecycle(t, false) }
func TestRuntimeAgentAPILifecycle(t *testing.T) { testAgentAPILifecycle(t, true) }
func testAgentAPILifecycle(t *testing.T, runtimeOnly bool) {
	if runtime.GOOS != "linux" {
		t.Skip("Required Linux gateway/API matrix; executed in the local Docker lab")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run the gateway/API lifecycle matrix as a dedicated non-root test user; the real preflight must reject root")
	}
	// Startup migration uses a disposable vault; keep its ciphertext out of other fixtures.
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = fmt.Sprintf("/vulnetic_agent_api_%d", time.Now().UnixNano())
	t.Setenv("VULNETIC_PG_DSN", u.String())
	// Build the fixture before enabling SaaS to exercise application ownership
	// checks with or without an RLS pool. Production startup still requires RLS.
	t.Setenv("VULNETIC_SAAS_MODE", "false")
	if runtimeOnly {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", "beta-integration-test-password-only")
	} else {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", "")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatal(err)
		}
		t.Skip("PostgreSQL required")
	}
	fixturePG := m.pg
	if runtimeOnly {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", "beta-integration-test-password-only")
		if err = m.pg.Close(); err != nil {
			t.Fatal(err)
		}
		// Provision schema/role as an operator, then discard that credential before the server starts.
		migrated, e := db.Open(u.String())
		if e != nil {
			t.Fatal(e)
		}
		fixturePG = migrated
		t.Cleanup(func() { _ = migrated.Close() })
		appDSN, e := config.PostgresAppDSN()
		if e != nil {
			t.Fatal(e)
		}
		t.Setenv("VULNETIC_PG_DSN", appDSN)
		m.pg, e = db.OpenRuntime(appDSN)
		if e != nil {
			t.Fatal(e)
		}
		m.assets = m.pg.Assets()
		m.interceptor = intercept.New(m.pg)
	}
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	state := t.TempDir()
	gatewayToken := strings.Repeat("local-gateway-test-credential", 2)
	tokenFile := filepath.Join(t.TempDir(), "gateway-token")
	if err = os.WriteFile(tokenFile, []byte(gatewayToken), 0600); err != nil {
		t.Fatal(err)
	}
	privateURL, publicURL := gatewayFixtureProcess(t, tokenFile)
	t.Setenv("VULNETIC_GATEWAY_URL", privateURL)
	t.Setenv("VULNETIC_GATEWAY_PUBLIC_URL", publicURL)
	t.Setenv("VULNETIC_GATEWAY_TOKEN_FILE", tokenFile)
	s := New(ctx, m, state, state, state)
	host := httptest.NewTLSServer(s.Handler())
	apiClient := host.Client()
	apiClient.Timeout = 15 * time.Second
	t.Setenv("VULNETIC_PUBLIC_URL", host.URL)
	var agents []context.CancelFunc
	t.Cleanup(func() {
		for _, cancel := range agents {
			cancel()
		}
		stop()
		host.Close()
		_ = m.Close()
	})
	call := func(token, method, path string, body any, want int) []byte {
		t.Helper()
		var reader io.Reader
		if body != nil {
			data, e := json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
			reader = bytes.NewReader(data)
		}
		request, e := http.NewRequest(method, host.URL+path, reader)
		if e != nil {
			t.Fatal(e)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := apiClient.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d: %s", method, path, response.StatusCode, want, data)
		}
		return data
	}
	type owner struct {
		accountID int64
		token     string
		target    db.SSHTarget
		join      string
		done      chan error
	}
	owners := make([]owner, 2)
	for i := range owners {
		name := fmt.Sprintf("agent-http-%d-%d", i, time.Now().UnixNano())
		account, user, e := m.pg.CreateAccountWithAdmin(name, name+"@example.test", "fixture", s.seedAccountCatalog)
		if e != nil {
			t.Fatal(e)
		}
		id := account.ID
		t.Cleanup(func() {
			_, _ = fixturePG.Exec(`DELETE FROM users WHERE account_id=$1`, id)
			_, _ = fixturePG.Exec(`DELETE FROM accounts WHERE id=$1`, id)
		})
		token, e := signJWTForPassword(s.jwtKey, account.ID, user.ID, "fixture")
		if e != nil {
			t.Fatal(e)
		}
		var profile struct {
			ID int64 `json:"id"`
		}
		secret := "synthetic-model-key-no-provider-call"
		if err := json.Unmarshal(call(token, "POST", "/api/llm/profiles", map[string]any{"name": "Before VPS", "format": "openai", "model": "fixture-only", "base_url": "https://fixture.invalid/v1", "api_key": secret}, 200), &profile); err != nil || profile.ID <= 0 {
			t.Fatal("profile could not be saved without a VPS", err)
		}
		call(token, "POST", "/api/llm/profiles/active", map[string]any{"id": profile.ID}, 200)
		if strings.Contains(string(call(token, "GET", "/api/llm/profiles", nil, 200)), secret) {
			t.Fatal("saved model credential exposed")
		}
		call(token, "POST", "/api/llm/profiles/test", map[string]any{"profile_id": profile.ID}, 400)
		call(token, "POST", "/api/llm/models", map[string]any{"profile_id": profile.ID}, 400)
		var result struct {
			Target  db.SSHTarget `json:"target"`
			Command string       `json:"command"`
		}
		if e = json.Unmarshal(call(token, "POST", "/api/execution-agents", map[string]any{"name": "Same executor name", "lease_seconds": 300}, 200), &result); e != nil {
			t.Fatal(e)
		}
		match := regexp.MustCompile(`VULNETIC_ENROLL_TOKEN='([^']+)'`).FindStringSubmatch(result.Command)
		if len(match) != 2 {
			t.Fatal("missing one-use enrollment")
		}
		agentCtx, cancel := context.WithCancel(t.Context())
		agents = append(agents, cancel)
		done := make(chan error, 1)
		executorDirectory := t.TempDir()
		go func(join string) {
			done <- reverseagent.Run(agentCtx, reverseagent.ClientConfig{ServerURL: host.URL, EnrollmentToken: join, Username: "fixture", Directory: executorDirectory, HTTPClient: host.Client()})
		}(match[1])
		owners[i] = owner{accountID: account.ID, token: token, target: result.Target, join: match[1], done: done}
		deadline := time.Now().Add(10 * time.Second)
		for !s.agentConnected(account.ID, result.Target.ID) {
			select {
			case e = <-done:
				t.Fatalf("agent exited during enrollment: %v", e)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("agent did not connect")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Run("WindowsForegroundEnrollment", func(t *testing.T) {
		var result struct {
			Target  db.SSHTarget `json:"target"`
			Command string       `json:"command"`
		}
		if err := json.Unmarshal(call(owners[0].token, "POST", "/api/execution-agents", map[string]any{"name": "Windows terminal", "lease_seconds": 300, "platform": "windows"}, 200), &result); err != nil || result.Target.OperatingSystem() != "windows" {
			t.Fatal("Windows executor creation failed", err)
		}
		call(owners[1].token, "POST", fmt.Sprintf("/api/execution-agents/%d/revoke", result.Target.ID), nil, 404)
		firstCommand := result.Command
		if err := json.Unmarshal(call(owners[0].token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", result.Target.ID), map[string]any{"lease_seconds": 300}, 200), &result); err != nil || result.Command == firstCommand {
			t.Fatal("explicit Windows replacement command failed", err)
		}
		pattern := regexp.MustCompile(`WriteAllText\(\$enrollment,'([^']+)'`)
		oldJoin, newJoin := pattern.FindStringSubmatch(firstCommand), pattern.FindStringSubmatch(result.Command)
		if len(oldJoin) != 2 || len(newJoin) != 2 {
			t.Fatal("foreground command omits enrollment")
		}
		pair, err := sshexec.GenerateKeypair("windows-fixture")
		if err != nil {
			t.Fatal(err)
		}
		for i, token := range []string{oldJoin[1], newJoin[1], newJoin[1]} {
			hash := sha256.Sum256([]byte(token))
			response := s.gatewayEvent(t.Context(), agentgateway.Message{Type: "enroll", Hash: hash[:], Request: &reverseagent.EnrollmentRequest{Platform: "windows", Username: "vulnetic-terminal", HostKey: pair.PublicKeyOpenSSH}})
			if i == 1 {
				if response.Error != "" || response.Enrollment == nil || response.Enrollment.LeaseSeconds != 300 {
					t.Fatal("Windows gateway enrollment failed")
				}
				stored, err := m.pg.GetSSHTarget(owners[0].accountID, result.Target.ID)
				if err != nil || stored.OperatingSystem() != "windows" || stored.AgentExpiresAt == nil || !stored.AgentExpiresAt.Equal(response.Enrollment.ExpiresAt) {
					t.Fatal("Windows lease or identity changed", err)
				}
			} else if response.Error == "" || response.Enrollment != nil {
				t.Fatal("replaced or replayed Windows enrollment accepted")
			}
		}
		call(owners[0].token, "POST", fmt.Sprintf("/api/execution-agents/%d/revoke", result.Target.ID), nil, 200)
		call(owners[0].token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", result.Target.ID), nil, 200)
	})
	// Restart the actual TLS platform on the same address and with the same vault keys.
	// Both authenticated agents must reconnect without enrollment or lease renewal.
	beforeExpiry := make([]time.Time, len(owners))
	for i, owner := range owners {
		target, err := m.pg.GetSSHTarget(owner.accountID, owner.target.ID)
		if err != nil {
			t.Fatal(err)
		}
		beforeExpiry[i] = *target.AgentExpiresAt
	}
	address := host.Listener.Addr().String()
	tlsConfig := host.TLS.Clone()
	stop()
	host.Close()
	ctx, stop = context.WithCancel(t.Context())
	defer stop()
	s = New(ctx, m, state, state, state)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	restarted := httptest.NewUnstartedServer(s.Handler())
	restarted.Listener.Close()
	restarted.Listener = listener
	restarted.TLS = tlsConfig
	restarted.StartTLS()
	host = restarted
	apiClient = host.Client()
	for i, owner := range owners {
		deadline := time.Now().Add(10 * time.Second)
		for {
			target, err := m.pg.GetSSHTarget(owner.accountID, owner.target.ID)
			if err != nil {
				t.Fatal(err)
			}
			if s.agentConnected(owner.accountID, owner.target.ID) && target.Status == "verified" {
				if !target.AgentExpiresAt.Equal(beforeExpiry[i]) {
					t.Fatal("restart extended the access deadline")
				}
				break
			}
			if time.Now().After(deadline) {
				result, diagnostic := s.sshPreflight(ctx, owner.accountID, owner.target.ID)
				t.Fatalf("agent did not reconnect: gateway_ready=%v connected=%v status=%s error=%s preflight=%s diagnostic=%v", s.gateway.Ready(), s.agentConnected(owner.accountID, owner.target.ID), target.Status, target.LastError, result, diagnostic)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}

	a, b := owners[0], owners[1]

	t.Run("existing execution waits for fresh authenticated binding", func(t *testing.T) {
		before, err := m.pg.GetSSHTarget(a.accountID, a.target.ID)
		if err != nil {
			t.Fatal(err)
		}
		expires, hostKey := *before.AgentExpiresAt, before.HostKey
		ex, closeExecutor, err := s.remoteExecutor(a.accountID, a.target.ID, fmt.Sprintf(".vulnetic/accounts/%d/reconnect-fixture", a.accountID))
		if err != nil {
			t.Fatal(err)
		}
		defer closeExecutor()
		s.remoteMu.Lock()
		oldRef := s.agentConnections[remoteOwner{a.accountID, a.target.ID}].gatewayRef
		s.remoteMu.Unlock()
		// Interrupt only the transport, preserving the persisted credential and absolute deadline.
		s.gateway.Revoke(oldRef)
		deadline := time.Now().Add(3 * time.Second)
		for {
			s.remoteMu.Lock()
			entry := s.agentConnections[remoteOwner{a.accountID, a.target.ID}]
			gone := entry == nil || entry.gatewayRef != oldRef
			s.remoteMu.Unlock()
			if gone {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("old transport was not disconnected")
			}
			time.Sleep(10 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var out bytes.Buffer
		h, err := ex.Start(ctx, "", nil, "printf fresh-run-connection", &out)
		if err != nil {
			t.Fatal("existing executor could not rebind", err)
		}
		if err = h.Wait(); err != nil || out.String() != "fresh-run-connection" {
			t.Fatal("reconnected operation failed", err)
		}
		after, err := m.pg.GetSSHTarget(a.accountID, a.target.ID)
		if err != nil || !after.AgentExpiresAt.Equal(expires) || after.HostKey != hostKey {
			t.Fatal("reconnection renewed access or changed identity", err)
		}
		s.remoteMu.Lock()
		newRef := s.agentConnections[remoteOwner{a.accountID, a.target.ID}].gatewayRef
		s.remoteMu.Unlock()
		if newRef == oldRef {
			t.Fatal("stale authenticated binding reused")
		}
	})
	t.Run("chat discovers only owned VPS executors", func(t *testing.T) {
		run := agent.WithRunInfo(t.Context(), agent.RunInfo{AccountID: a.accountID})
		result, err := s.toolListVPS().Call(run, json.RawMessage(`{}`), nil)
		if err != nil || result.IsError {
			t.Fatal("VPS discovery failed", err, result.Flatten())
		}
		var listed struct {
			VPS []struct {
				ID    int64 `json:"id"`
				Ready bool  `json:"ready"`
			} `json:"vps"`
		}
		if json.Unmarshal([]byte(result.Flatten()), &listed) != nil || len(listed.VPS) != 1 || listed.VPS[0].ID != a.target.ID || !listed.VPS[0].Ready {
			t.Fatal("wrong owned VPS list", result.Flatten())
		}
		result, err = s.toolSpawnTask().Call(run, json.RawMessage(fmt.Sprintf(`{"description":"fixture","goal":"fixture","ssh_target_id":%d}`, b.target.ID)), nil)
		if err != nil || !result.IsError {
			t.Fatal("spawn accepted a foreign VPS")
		}
		var second struct {
			Target db.SSHTarget `json:"target"`
		}
		if err = json.Unmarshal(call(a.token, "POST", "/api/execution-agents", map[string]any{"name": "Selection-only fixture", "lease_seconds": 300}, 200), &second); err != nil {
			t.Fatal(err)
		}
		target, _ := m.pg.GetSSHTarget(a.accountID, a.target.ID)
		if _, err = fixturePG.Exec(`UPDATE ssh_targets SET host_key=$1,preflight=$2,status='verified',agent_expires_at=now()+interval '1 hour' WHERE id=$3 AND account_id=$4`, target.HostKey, target.Preflight, second.Target.ID, a.accountID); err != nil {
			t.Fatal(err)
		}
		s.remoteMu.Lock()
		s.agentConnections[remoteOwner{a.accountID, second.Target.ID}] = &agentConnection{}
		s.remoteMu.Unlock()
		result, err = s.toolSpawnTask().Call(run, json.RawMessage(`{"description":"fixture","goal":"fixture"}`), nil)
		s.remoteMu.Lock()
		delete(s.agentConnections, remoteOwner{a.accountID, second.Target.ID})
		s.remoteMu.Unlock()
		call(a.token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", second.Target.ID), nil, 200)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "ask the user") {
			t.Fatal("ambiguous VPS selection did not request a chat answer", result.Flatten())
		}
	})

	for _, seconds := range []int{10800, 86400, 259200, 604800} {
		var result struct {
			Target  db.SSHTarget `json:"target"`
			Command string       `json:"command"`
		}
		if err := json.Unmarshal(call(a.token, "POST", "/api/execution-agents", map[string]any{"name": "Duration check", "lease_seconds": seconds}, 200), &result); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(result.Command, fmt.Sprintf("VULNETIC_LEASE_SECONDS=%d ", seconds)) {
			t.Fatal("installer duration differs from request")
		}
		call(a.token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", result.Target.ID), map[string]any{"lease_seconds": seconds}, 200)
		call(a.token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", result.Target.ID), map[string]any{"lease_seconds": 604801}, 400)
	}
	for _, seconds := range []int{299, 604801} {
		call(a.token, "POST", "/api/execution-agents", map[string]any{"name": "Invalid duration", "lease_seconds": seconds}, 400)
	}

	call(b.token, "GET", fmt.Sprintf("/api/ssh-targets/%d", a.target.ID), nil, 404)
	call(b.token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", a.target.ID), nil, 404)
	call(b.token, "POST", fmt.Sprintf("/api/execution-agents/%d/revoke", a.target.ID), map[string]any{}, 404)
	call(b.token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", a.target.ID), map[string]any{"lease_seconds": 300}, 404)
	call(a.join, "POST", "/agent/enroll", reverseagent.EnrollmentRequest{HostKey: a.target.PublicKeyOpenSSH, Username: "fixture"}, 401)
	call(a.token, "GET", fmt.Sprintf("/api/ssh-targets/%d/host-key", a.target.ID), nil, 404)
	call(a.token, "POST", "/api/ssh-targets", map[string]any{"name": "inbound", "host": "127.0.0.1", "username": "root", "port": 22}, 409)
	if runtime.GOOS == "linux" {
		deadline := time.Now().Add(10 * time.Second)
		for {
			target, e := m.pg.GetSSHTarget(a.accountID, a.target.ID)
			if e != nil {
				t.Fatal(e)
			}
			if target.Status == db.SSHTargetVerified {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("agent preflight did not pass")
			}
			time.Sleep(20 * time.Millisecond)
		}
		data := call(a.token, "POST", "/api/tools/custom/test", map[string]any{"ssh_target_id": a.target.ID, "kind": "command", "exec": map[string]any{"command": "printf AGENT_RUNTIME_OK", "timeout_ms": 2000}, "params": map[string]any{}}, 200)
		var result struct {
			IsError bool `json:"is_error"`
		}
		if json.Unmarshal(data, &result) != nil || result.IsError || !strings.Contains(string(data), "AGENT_RUNTIME_OK") {
			t.Fatal("remote command did not run through the temporary agent")
		}
	}

	t.Run("CVE authorization, encrypted evidence and account isolation", func(t *testing.T) {
		testCVEVerificationAPI(t, s, m, fixturePG, call, a.accountID, a.token, b.token, a.target.ID)
	})

	if runtime.GOOS == "linux" {
		t.Run("task executor recovery preserves history and evidence", func(t *testing.T) {
			var old struct {
				Target db.SSHTarget `json:"target"`
			}
			if err := json.Unmarshal(call(a.token, "POST", "/api/execution-agents", map[string]any{"name": "Expired task VPS", "lease_seconds": 300}, 200), &old); err != nil {
				t.Fatal(err)
			}
			if _, err := fixturePG.Exec(`UPDATE ssh_targets SET agent_expires_at=now()-interval '1 second' WHERE id=$1 AND account_id=$2`, old.Target.ID, a.accountID); err != nil {
				t.Fatal(err)
			}
			task, err := m.CreateTaskWithOptions("Preserved task", "fixture", db.TaskCreateOptions{AccountID: a.accountID, SSHTargetID: &old.Target.ID})
			if err != nil {
				t.Fatal(err)
			}
			taskNum, err := strconv.ParseInt(task.ID, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.evictTaskAgents(task.ID); _ = m.pg.DeleteTask(taskNum); m.forgetTask(task.ID, taskNum) }()
			if err = m.SetTaskPaused(task.ID, true); err != nil {
				t.Fatal(err)
			}
			activityID, err := task.Store.AppendActivity(db.Activity{Worker: "system", Kind: "text", Summary: "Preserved history fixture"})
			if err != nil {
				t.Fatal(err)
			}
			findingID, err := m.pg.ForAccount(a.accountID).AddFinding(taskNum, 0, "fixture", "Saved finding", "low", "summary", "saved evidence", "fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.pg.RecordExecutionProof(t.Context(), db.ExecutionProof{AccountID: a.accountID, TaskID: &taskNum, RunID: "original-run", Tool: "fixture", Input: json.RawMessage(`{"fixture":true}`), Output: "original proof"}); err != nil {
				t.Fatal(err)
			}
			proofsBefore, err := m.pg.ExecutionProofs(a.accountID, &taskNum, nil)
			if err != nil {
				t.Fatal(err)
			}
			findingBefore, err := m.pg.GetFinding(findingID)
			if err != nil {
				t.Fatal(err)
			}
			originalBundle := s.agentsForTask(task)
			path := "/api/tasks/" + task.ID + "/ssh-target"
			call(b.token, "PUT", path, map[string]any{"ssh_target_id": b.target.ID}, 404)
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": b.target.ID}, 404)
			if err = m.pg.SetTaskSSHTarget(a.accountID, taskNum, &b.target.ID); err == nil {
				t.Fatal("repository allowed a foreign executor")
			}
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": nil}, 400)
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": old.Target.ID}, 409)
			if err = m.SetTaskPaused(task.ID, false); err != nil {
				t.Fatal(err)
			}
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": a.target.ID}, 409)
			if err = m.SetTaskPaused(task.ID, true); err != nil {
				t.Fatal(err)
			}
			if !s.engine.beginTaskOperation(task.ID) {
				t.Fatal("operation not admitted")
			}
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": a.target.ID}, 409)
			s.engine.decInflight(task.ID)
			s.chatMu.Lock()
			s.chatBusy[task.ID] = true
			s.chatMu.Unlock()
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": a.target.ID}, 409)
			s.chatMu.Lock()
			delete(s.chatBusy, task.ID)
			s.chatMu.Unlock()
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": a.target.ID}, 200)
			var dto TaskDTO
			if err = json.Unmarshal(call(a.token, "GET", "/api/tasks/"+task.ID, nil, 200), &dto); err != nil || dto.SSHTargetID == nil || *dto.SSHTargetID != a.target.ID {
				t.Fatal("task response did not expose its current VPS", err)
			}
			replacement := s.agentsForTask(task)
			if replacement == originalBundle {
				t.Fatal("old executor bundle was retained")
			}
			var output bytes.Buffer
			command, err := replacement.sshExecutor.Start(t.Context(), "", nil, "printf 'RECOVERED_EXECUTOR '; pwd", &output)
			if err != nil {
				t.Fatal(err)
			}
			if err = command.Wait(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), fmt.Sprintf(".vulnetic/accounts/%d/tasks/%s", a.accountID, task.ID)) {
				t.Fatal("replacement command did not use the original task workspace")
			}
			// Simulate deletion of the prior record; replacement must also recover a NULL FK.
			if err = m.SetTaskSSHTarget(a.accountID, task.ID, &old.Target.ID); err != nil {
				t.Fatal(err)
			}
			call(a.token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", old.Target.ID), nil, 200)
			call(a.token, "PUT", path, map[string]any{"ssh_target_id": a.target.ID}, 200)
			t.Run("saved task files restore after deleting old VPS", func(t *testing.T) {
				testTaskFilesRecovery(t, s, host.URL, apiClient, task, a.token, b.token)
			})
			persisted, err := m.pg.GetTask(taskNum)
			if err != nil || persisted == nil || persisted.ExplorationID != task.ExpID || persisted.SSHTargetID == nil || *persisted.SSHTargetID != a.target.ID || !persisted.Paused {
				t.Fatal("task identity/lifecycle changed during recovery", err)
			}
			proofsAfter, err := m.pg.ExecutionProofs(a.accountID, &taskNum, nil)
			if err != nil {
				t.Fatal(err)
			}
			findingAfter, err := m.pg.GetFinding(findingID)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(proofsBefore)
			after, _ := json.Marshal(proofsAfter)
			if !bytes.Equal(before, after) {
				t.Fatal("recovery modified original execution evidence")
			}
			before, _ = json.Marshal(findingBefore)
			after, _ = json.Marshal(findingAfter)
			if !bytes.Equal(before, after) {
				t.Fatal("recovery modified the saved finding")
			}
			var summary string
			if err = fixturePG.QueryRow(`SELECT summary FROM activity WHERE id=$1 AND exploration_id=$2`, activityID, task.ExpID).Scan(&summary); err != nil || summary != "Preserved history fixture" {
				t.Fatal("task history was lost", err)
			}
		})
	}
	call(a.token, "POST", fmt.Sprintf("/api/execution-agents/%d/revoke", a.target.ID), map[string]any{}, 200)
	select {
	case <-a.done:
	case <-time.After(4 * time.Second):
		t.Fatal("revocation did not stop the agent")
	}
	if s.agentConnected(a.accountID, a.target.ID) {
		t.Fatal("revoked agent remained connected")
	}
	if !s.agentConnected(b.accountID, b.target.ID) {
		t.Fatal("revoking account A interrupted account B")
	}
	call(a.token, "GET", fmt.Sprintf("/api/ssh-targets/%d", a.target.ID), nil, 200)
	var record struct {
		Target  db.SSHTarget `json:"target"`
		Command string       `json:"command"`
	}
	if json.Unmarshal(call(a.token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", a.target.ID), map[string]any{"lease_seconds": 600}, 200), &record) != nil || record.Target.ID != a.target.ID || record.Command == "" {
		t.Fatal("fresh enrollment did not preserve executor identity")
	}
	events, e := m.pg.ListAudit(a.accountID)
	if e != nil {
		t.Fatal(e)
	}
	data, e := json.Marshal(events)
	if e != nil || strings.Contains(string(data), a.join) {
		t.Fatal("enrollment token leaked into audit")
	}
	if _, e = fixturePG.Exec(`UPDATE ssh_targets SET agent_expires_at=now()-interval '1 second' WHERE id=$1`, b.target.ID); e != nil {
		t.Fatal(e)
	}
	select {
	case <-b.done:
	case <-time.After(8 * time.Second):
		t.Fatal("an expired lease kept its agent connected")
	}
	// Client shutdown can precede the server's deferred registry cleanup.
	cleanupDeadline := time.Now().Add(2 * time.Second)
	for s.agentConnected(b.accountID, b.target.ID) {
		if time.Now().After(cleanupDeadline) {
			t.Fatal("expired agent remained available")
		}
		time.Sleep(10 * time.Millisecond)
	}
	history, err := m.pg.ForAccount(a.accountID).CreateTask("Preserved executor history", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = fixturePG.Exec(`DELETE FROM tasks WHERE id=$1 AND account_id=$2`, history.ID, a.accountID)
	})
	if _, err = fixturePG.Exec(`UPDATE tasks SET ssh_target_id=$1,paused=true WHERE id=$2 AND account_id=$3`, a.target.ID, history.ID, a.accountID); err != nil {
		t.Fatal(err)
	}
	call(a.token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", a.target.ID), nil, 200)
	call(a.token, "GET", fmt.Sprintf("/api/ssh-targets/%d", a.target.ID), nil, 404)
	call(b.token, "GET", fmt.Sprintf("/api/ssh-targets/%d", b.target.ID), nil, 200)
	var description string
	var binding sql.NullInt64
	if err = fixturePG.QueryRow(`SELECT description,ssh_target_id FROM tasks WHERE id=$1 AND account_id=$2`, history.ID, a.accountID).Scan(&description, &binding); err != nil || description != "Preserved executor history" || binding.Valid {
		t.Fatal("deleting executor removed task history or retained its binding", err)
	}
	// Delete a connected executor as well: access must stop before the row disappears.
	if err = json.Unmarshal(call(b.token, "POST", fmt.Sprintf("/api/execution-agents/%d/install-command", b.target.ID), map[string]any{"lease_seconds": 300}, 200), &record); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`VULNETIC_ENROLL_TOKEN='([^']+)'`).FindStringSubmatch(record.Command)
	if len(match) != 2 {
		t.Fatal("missing enrollment")
	}
	agentCtx, cancelAgent := context.WithCancel(ctx)
	agents = append(agents, cancelAgent)
	deletedDone := make(chan error, 1)
	go func() {
		deletedDone <- reverseagent.Run(agentCtx, reverseagent.ClientConfig{ServerURL: host.URL, EnrollmentToken: match[1], Username: "fixture", HTTPClient: apiClient})
	}()
	deadline := time.Now().Add(8 * time.Second)
	for !s.agentConnected(b.accountID, b.target.ID) {
		select {
		case err := <-deletedDone:
			t.Fatalf("agent failed before deletion: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not reconnect for deletion check")
		}
		time.Sleep(10 * time.Millisecond)
	}
	call(b.token, "DELETE", fmt.Sprintf("/api/ssh-targets/%d", b.target.ID), nil, 200)
	select {
	case <-deletedDone:
	case <-time.After(4 * time.Second):
		t.Fatal("deletion did not close active agent")
	}
	if s.agentConnected(b.accountID, b.target.ID) {
		t.Fatal("deleted executor remained connected")
	}
	call(b.token, "GET", fmt.Sprintf("/api/ssh-targets/%d", b.target.ID), nil, 404)
}

func TestBetaAgentInstallerLifetimeBounds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell contract runs in the mandatory Linux validation")
	}
	prefix, _, ok := strings.Cut(agentInstallScript, "test \"$(uname -s)\"")
	if !ok {
		t.Fatal("installer lifetime check boundary not found")
	}
	for _, seconds := range []string{"299", "10800", "86400", "259200", "604800", "604801", "not-a-number"} {
		t.Run(seconds, func(t *testing.T) {
			command := exec.CommandContext(t.Context(), "sh", "-c", prefix+"\nprintf 'accepted'\n")
			command.Env = []string{"PATH=/usr/bin:/bin", "VULNETIC_ENROLL_TOKEN=fixture", "VULNETIC_LEASE_SECONDS=" + seconds}
			output, err := command.CombinedOutput()
			valid := seconds == "10800" || seconds == "86400" || seconds == "259200" || seconds == "604800"
			if valid && (err != nil || string(output) != "accepted") {
				t.Fatalf("installer rejected chosen lifetime: %v", err)
			}
			if !valid && err == nil {
				t.Fatal("installer accepted an invalid lifetime")
			}
		})
	}
}

func TestBetaPersistentAgentInstallerUnit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installer contract requires the mandatory Linux lab")
	}
	script := strings.ReplaceAll(agentInstallScript, "__PLATFORM_URL__", "'https://fixture.example.test'")
	syntax := exec.CommandContext(t.Context(), "sh", "-n")
	syntax.Stdin = strings.NewReader(script)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("installer shell syntax: %v %s", err, output)
	}
	_, python, ok := strings.Cut(script, "<<'UNIT'\n")
	if !ok {
		t.Fatal("unit writer missing")
	}
	python, _, ok = strings.Cut(python, "\nUNIT\n")
	if !ok {
		t.Fatal("unit boundary missing")
	}
	directory := filepath.Join(t.TempDir(), "vulnetic-agent.ABCD1234")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent", "cleanup.sh"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	unit := filepath.Join(t.TempDir(), "vulnetic-agent-ABCD1234.service")
	command := exec.CommandContext(t.Context(), "python3", "-", unit, directory, "https://fixture.example.test", "/home/fixture%user", "10800", "multi-user.target")
	command.Stdin = strings.NewReader(python)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unit generation: %v %s", err, output)
	}
	data, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"WantedBy=multi-user.target", "Restart=on-failure", "RuntimeMaxSec=10800", "fixture%%user", "StandardInput=null", "ExecStopPost=", "User=vulnetic-agent", "Group=vulnetic-agent", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "LoadCredentialEncrypted=vulnetic-state-key:", "ProtectSystem=strict", "ProtectHome=yes", "ReadWritePaths="} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatalf("unit missing %s", expected)
		}
	}
	// Verify service syntax with executable fixtures accessible to an unprivileged verifier.
	verifyData := strings.ReplaceAll(string(data), filepath.Join(directory, "agent"), "/usr/bin/true")
	verifyData = strings.ReplaceAll(verifyData, filepath.Join(directory, "cleanup.sh"), "/usr/bin/true")
	if err := os.WriteFile(unit, []byte(verifyData), 0600); err != nil {
		t.Fatal(err)
	}
	verify := exec.CommandContext(t.Context(), "systemd-analyze", "verify", unit)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("systemd unit invalid: %v %s", err, output)
	}
}
