package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/cvecheck"
	"strings"
	"testing"
	"time"
)

func TestCVEAuthorizationAndProofIsolation(t *testing.T) {
	d := betaTestDB(t)
	a, b := betaAccount(t, d, "cve-a"), betaAccount(t, d, "cve-b")
	d.ConfigureVault(bytes.Repeat([]byte{81}, 32), true)
	ctx := t.Context()
	var user int64
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`UPDATE cve_check_runs SET proof_id=NULL WHERE account_id IN ($1,$2)`, a.ID, b.ID)
		d.Exec(`DELETE FROM execution_proofs WHERE account_id IN ($1,$2)`, a.ID, b.ID)
		d.Exec(`DELETE FROM cve_check_runs WHERE account_id IN ($1,$2)`, a.ID, b.ID)
		d.Exec(`DELETE FROM cve_authorizations WHERE account_id IN ($1,$2)`, a.ID, b.ID)
	})
	target, err := d.ForAccount(a.ID).CreateExecutionAgent(ctx, a.ID, "CVE lab", 3600, bytes.Repeat([]byte{31}, 32), []byte("encrypted"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32), "fixture-host", "fixture"); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("CVE fixture", "owned lab", TaskCreateOptions{AccountID: a.ID, UserID: user, SSHTargetID: &target.ID})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := d.ForAccount(a.ID).Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: "http://fixture.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	recipe, _ := cvecheck.Lookup("CVE-2021-28164")
	dest := cvecheck.Target{URL: "http://fixture.invalid", CanaryID: strings.Repeat("a", 32), Token: "vulnetic-proof:" + strings.Repeat("b", 32), ControlPath: "/vulnetic-control/" + strings.Repeat("a", 32) + ".txt", Headers: map[string]string{"Authorization": "Bearer cve-fixture-secret"}}
	create := func() *CVEAuthorization {
		t.Helper()
		auth, err := d.CreateCVEAuthorization(ctx, CVEAuthorization{AccountID: a.ID, UserID: user, TaskID: task.ID, AssetID: asset, ExecutorID: target.ID, RecipeID: recipe.ID, RecipeDigest: recipe.Digest(), TargetURL: dest.URL, Target: dest, RemainingRuns: 1})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	auth := create()
	if auth.ExpiresAt.After(time.Now().Add(16 * time.Minute)) {
		t.Fatal("unbounded grant")
	}
	var stored string
	d.QueryRow(`SELECT payload FROM cve_authorizations WHERE id=$1`, auth.ID).Scan(&stored)
	if strings.Contains(stored, "cve-fixture-secret") {
		t.Fatal("authorization secret persisted in clear")
	}
	if _, err = d.CVEAuthorization(ctx, b.ID, auth.ID); err == nil {
		t.Fatal("foreign grant readable")
	}
	run, _, err := d.StartCVECheck(ctx, a.ID, user, auth.ID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	second := create()
	if _, _, err = d.StartCVECheck(ctx, a.ID, user, second.ID, task.ID); err == nil {
		t.Fatal("concurrent verification accepted")
	}
	unchanged, _ := d.CVEAuthorization(ctx, a.ID, second.ID)
	if unchanged.RemainingRuns != 1 {
		t.Fatal("failed admission consumed grant")
	}
	if _, _, err = d.StartCVECheck(ctx, b.ID, user, auth.ID, task.ID); err == nil {
		t.Fatal("foreign grant executed")
	}
	result := cvecheck.Result{Version: cvecheck.Version, RecipeID: recipe.ID, RecipeDigest: recipe.Digest(), Target: dest.URL, Outcome: "reproduced", Healthy: true, ControlValid: true, BoundaryProtected: true, NegativeClean: true, Reproductions: 2, Observations: make([]cvecheck.Observation, 6)}
	if err = d.FinishCVECheck(ctx, run, result, nil); err == nil {
		t.Fatal("text-only reproduction completed")
	}
	proof, err := d.InsertExecutionProof(ctx, ExecutionProof{AccountID: a.ID, UserID: user, TaskID: &task.ID, AssetID: &asset, ExecutorID: &target.ID, VerificationRunID: &run.ID, RunID: fmt.Sprint("check-", run.ID), Tool: "verify_cve_candidate", Input: json.RawMessage(`{"fixture":true}`), Output: "controlled fixture proof", FullArtifactID: "00000000-0000-0000-0000-000000000001", SchemaVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.FinishCVECheck(ctx, run, result, &proof); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.StartCVECheck(ctx, a.ID, user, auth.ID, task.ID); err == nil {
		t.Fatal("exhausted grant reused")
	}
	runs, err := d.CVEChecks(a.ID, task.ID)
	if err != nil || len(runs) != 1 || runs[0].Outcome != "reproduced" {
		t.Fatal(runs, err)
	}
	foreign, err := d.CVEChecks(b.ID, task.ID)
	if err != nil || len(foreign) != 0 {
		t.Fatal("foreign history leaked", err)
	}
	finding, err := d.ForAccount(a.ID).Exploration(task.ExplorationID).RecordFinding(WithExecutionOwner(ctx, a.ID, user), RecordFindingInput{TaskID: task.ID, Summary: "Controlled finding", Evidence: "Controlled proof", VulnClass: recipe.ID, Severity: "low", Worker: "fixture", AssetIDs: []int64{asset}})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ForAccount(a.ID).VerifyFinding(ctx, a.ID, user, finding.FindingID, []int64{proof}, "Review positive, negative and reproduction controls"); err != nil {
		t.Fatal(err)
	}
	otherAsset, err := d.ForAccount(a.ID).Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: "http://other.fixture.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := d.ForAccount(a.ID).Exploration(task.ExplorationID).RecordFinding(WithExecutionOwner(ctx, a.ID, user), RecordFindingInput{TaskID: task.ID, Summary: "Other target", Evidence: "Different target", VulnClass: recipe.ID, Severity: "low", Worker: "fixture", AssetIDs: []int64{otherAsset}})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ForAccount(a.ID).VerifyFinding(ctx, a.ID, user, unrelated.FindingID, []int64{proof}, "Same task is not enough to attribute a vulnerability"); err == nil {
		t.Fatal("proof of different asset accepted")
	}
	d.Exec(`UPDATE cve_authorizations SET expires_at=now()-interval '1 second' WHERE id=$1`, second.ID)
	if _, _, err = d.StartCVECheck(ctx, a.ID, user, second.ID, task.ID); err == nil {
		t.Fatal("expired grant executed")
	}
	rebind := create()
	d.Exec(`UPDATE tasks SET ssh_target_id=NULL WHERE id=$1`, task.ID)
	if _, _, err = d.StartCVECheck(ctx, a.ID, user, rebind.ID, task.ID); err == nil {
		t.Fatal("grant survived executor replacement")
	}
}
func TestCVEFailedEvidenceCannotVerify(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "cve-failed")
	var user int64
	d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&user)
	task, err := d.CreateTaskWithOptions("Evidence fixture", "owned lab", TaskCreateOptions{AccountID: a.ID, UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.ForAccount(a.ID).Exploration(task.ExplorationID).RecordFinding(WithExecutionOwner(context.Background(), a.ID, user), RecordFindingInput{TaskID: task.ID, Summary: "Candidate", Evidence: "Needs actual evidence", VulnClass: "fixture", Severity: "low", Worker: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"failed", "incomplete", "truncated"} {
		p := ExecutionProof{AccountID: a.ID, UserID: user, TaskID: &task.ID, RunID: kind, Tool: "Bash", Input: json.RawMessage(`{}`), Output: "unreliable evidence", Failed: kind == "failed", CaptureIncomplete: kind == "incomplete", Truncated: kind == "truncated"}
		id, err := d.InsertExecutionProof(t.Context(), p)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.ForAccount(a.ID).VerifyFinding(t.Context(), a.ID, user, f.FindingID, []int64{id}, "Review this intentionally unreliable fixture"); err == nil {
			t.Fatal("unusable proof accepted", kind)
		}
	}
}
