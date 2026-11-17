package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
)

func testCVEVerificationAPI(t *testing.T, s *Server, m *Manager, fixturePG *db.DB, call func(string, string, string, any, int) []byte, accountID int64, token, foreign string, executorID int64) {
	t.Helper()
	id, marker := strings.Repeat("a", 32), "vulnetic-proof:"+strings.Repeat("b", 32)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vulnetic-control/"+id+".txt" || strings.Contains(r.RequestURI, "/%2e/WEB-INF/vulnetic-"+id+".txt") {
			fmt.Fprint(w, marker)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, "Healthy controlled fixture")
			return
		}
		http.NotFound(w, r)
	}))
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	target.Listener = listener
	target.Start()
	origin, _ := url.Parse(target.URL)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, address := range addresses {
		ip, _, e := net.ParseCIDR(address.String())
		if e == nil && ip.To4() != nil && !ip.IsLoopback() {
			origin.Host = net.JoinHostPort(ip.String(), origin.Port())
			found = true
			break
		}
	}
	if !found {
		t.Fatal("isolated Linux fixture needs its private container address")
	}
	target.URL = origin.String()
	defer target.Close()
	task, err := m.CreateTaskWithOptions("CVE API fixture", "Controlled local target", db.TaskCreateOptions{AccountID: accountID, SSHTargetID: &executorID})
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := parseTaskID(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fixturePG.Exec(`UPDATE cve_check_runs SET proof_id=NULL WHERE task_id=$1`, taskID)
		fixturePG.Exec(`DELETE FROM execution_proofs WHERE task_id=$1`, taskID)
		fixturePG.Exec(`DELETE FROM cve_check_runs WHERE task_id=$1`, taskID)
		fixturePG.Exec(`DELETE FROM cve_authorizations WHERE task_id=$1`, taskID)
		s.evictTaskAgents(task.ID)
		_ = m.pg.DeleteTask(taskID)
		m.forgetTask(task.ID, taskID)
	})
	asset, err := m.pg.ForAccount(accountID).Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: target.URL, TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/tasks/" + task.ID + "/verification"
	call(foreign, "GET", base, nil, 404)
	call(token, "GET", base, nil, 200)
	input := map[string]any{"asset_id": asset, "recipe_id": "CVE-2021-28164", "canary_id": id, "token": marker, "confirmed": false}
	call(token, "POST", base+"/authorizations", input, 422)
	input["confirmed"] = true
	t.Setenv("VULNETIC_CVE_LAB_MODE", "true")
	var grant struct {
		ID int64 `json:"id"`
	}
	if err = json.Unmarshal(call(token, "POST", base+"/authorizations", input, 201), &grant); err != nil {
		t.Fatal(err)
	}
	call(foreign, "POST", base+"/execute", map[string]any{"authorization_id": grant.ID}, 404)
	var run db.CVECheckRun
	if err = json.Unmarshal(call(token, "POST", base+"/execute", map[string]any{"authorization_id": grant.ID}, 200), &run); err != nil {
		t.Fatal(err)
	}
	if run.Outcome != "reproduced" || run.ProofID == nil {
		t.Fatalf("controlled remote check failed: %s", run.Outcome)
	}
	call(token, "POST", base+"/execute", map[string]any{"authorization_id": grant.ID}, 409)
	proof, err := m.pg.ExecutionProofByID(accountID, *run.ProofID)
	if err != nil {
		t.Fatal(err)
	}
	full, err := s.loadProofArtifact(proof)
	if err != nil || !strings.Contains(full.Output, marker) {
		t.Fatal("full execution bytes missing", err)
	}
	call(foreign, "GET", fmt.Sprintf("/api/execution-proofs/%d/artifact", proof.ID), nil, 404)
	call(token, "GET", fmt.Sprintf("/api/execution-proofs/%d/artifact", proof.ID), nil, 200)
	// Large captures retain full bytes while the list preview is bounded and redacted.
	payload := "Authorization: Bearer fixture-only-secret\n" + strings.Repeat("x", 300<<10)
	saved, err := s.persistProof(t.Context(), db.ExecutionProof{AccountID: accountID, TaskID: &taskID, RunID: "large-fixture", Tool: "fixture", Input: json.RawMessage(`{}`), Output: payload})
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.pg.ExecutionProofByID(accountID, saved)
	if err != nil || !p.Truncated || strings.Contains(p.Output, "fixture-only-secret") {
		t.Fatal("unsafe preview", err)
	}
	original, err := s.loadProofArtifact(p)
	if err != nil || original.Output != payload {
		t.Fatal("full capture lost bytes", err)
	}
	sealed, err := s.readAccountFile(accountID, "execution-proofs/"+p.FullArtifactID+".vlt")
	if err != nil || bytes.Contains(sealed, []byte("fixture-only-secret")) {
		t.Fatal("artifact not encrypted", err)
	}
	if err = s.writeAccountFile(accountID, "execution-proofs/"+p.FullArtifactID+".vlt", []byte("corrupt fixture")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadProofArtifact(p); err == nil {
		t.Fatal("corrupted evidence accepted")
	}
	call(token, "GET", fmt.Sprintf("/api/execution-proofs/%d/artifact", saved), nil, 503)
	root, err := s.accountStorage(accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := artifactquota.Bytes(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.persistProof(t.Context(), db.ExecutionProof{AccountID: accountID, UserID: -1, TaskID: &taskID, RunID: "rejected-actor-fixture", Tool: "fixture", Input: json.RawMessage(`{}`), Output: "fixture evidence"})
	if err == nil {
		t.Fatal("invalid actor accepted")
	}
	after, err := artifactquota.Bytes(root)
	if err != nil || before != after {
		t.Fatal("failed insert consumed artifact quota", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	committed, err := s.persistProof(cancelled, db.ExecutionProof{AccountID: accountID, TaskID: &taskID, ExecutorID: &executorID, RunID: "cancelled-fixture", Tool: "fixture", Input: json.RawMessage(`{}`), Output: "final received output"})
	if err != nil {
		t.Fatal("cancellation lost received evidence", err)
	}
	final, err := m.pg.ExecutionProofByID(accountID, committed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadProofArtifact(final); err != nil {
		t.Fatal(err)
	}
	changed := executorID + 1
	final.ExecutorID = &changed
	if _, err = s.loadProofArtifact(final); err == nil {
		t.Fatal("artifact accepted altered executor attribution")
	}
	// Retain the encrypted bytes while simulating a rejected/lost metadata commit.
	recoverable, err := m.pg.ExecutionProofByID(accountID, committed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixturePG.Exec(`DELETE FROM execution_proofs WHERE id=$1`, committed); err != nil {
		t.Fatal(err)
	}
	report, err := ReconcileProofArtifacts(t.Context(), m.pg, s.vaultKey, m.dir, accountID, false)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, row := range report {
		if row.ArtifactID == recoverable.FullArtifactID {
			found = row.Status == "recoverable"
		}
	}
	if !found {
		t.Fatal("orphan not identified without mutating")
	}
	if _, err = ReconcileProofArtifacts(t.Context(), m.pg, s.vaultKey, m.dir, accountID, true); err != nil {
		t.Fatal(err)
	}
	var restoredID int64
	if err = m.pg.ForAccount(accountID).QueryRow(`SELECT id FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, accountID, recoverable.FullArtifactID).Scan(&restoredID); err != nil {
		t.Fatal(err)
	}
	restored, err := m.pg.ExecutionProofByID(accountID, restoredID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadProofArtifact(restored); err != nil {
		t.Fatal("recovered bytes invalid", err)
	}
	if _, err = ReconcileProofArtifacts(t.Context(), m.pg, s.vaultKey, m.dir, accountID, true); err != nil {
		t.Fatal("recovery is not idempotent", err)
	}
}
