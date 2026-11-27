package db

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FindingVerificationPlaybook is the #9 read side: once a finding is verified it
// must hand back the recorded steps, the confirmed claim and the exact proofs the
// reviewer linked — nil until then, current=false once the evidence moves on.
// Needs Postgres (betaTestDB); skipped where no DB is configured.
func TestFindingVerificationPlaybook(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "pb-a")
	d.ConfigureVault(bytes.Repeat([]byte{81}, 32), true)
	ctx := t.Context()
	var user int64
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM execution_proofs WHERE account_id=$1`, a.ID)
	})
	target, err := d.ForAccount(a.ID).CreateExecutionAgent(ctx, a.ID, "PB lab", 3600, bytes.Repeat([]byte{71}, 32), []byte("encrypted"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, bytes.Repeat([]byte{71}, 32), bytes.Repeat([]byte{72}, 32), "fixture-host", "fixture"); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("PB fixture", "owned lab", TaskCreateOptions{AccountID: a.ID, UserID: user, SSHTargetID: &target.ID})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := d.ForAccount(a.ID).Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: "http://fixture.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := d.InsertExecutionProof(ctx, ExecutionProof{AccountID: a.ID, UserID: user, TaskID: &task.ID, AssetID: &asset, ExecutorID: &target.ID, RunID: "pb-run-1", Tool: "Bash", Input: json.RawMessage(`{"cmd":"curl"}`), Output: "reproduced", FullArtifactID: "00000000-0000-0000-0000-000000000001", SchemaVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := d.ForAccount(a.ID).Exploration(task.ExplorationID).RecordFinding(WithExecutionOwner(ctx, a.ID, user), RecordFindingInput{TaskID: task.ID, Summary: "Auth bypass on /admin", Evidence: "200 without a session", VulnClass: "A01", Severity: "high", Worker: "fixture", AssetIDs: []int64{asset}})
	if err != nil {
		t.Fatal(err)
	}

	// No verification yet → no playbook.
	if pb, err := d.ForAccount(a.ID).FindingVerificationPlaybook(ctx, a.ID, finding.FindingID); err != nil || pb != nil {
		t.Fatalf("unverified finding: pb=%v err=%v, want nil,nil", pb, err)
	}

	const steps = "1. GET /admin with no cookie. 2. Observe HTTP 200 and the admin panel."
	if err = d.ForAccount(a.ID).VerifyFinding(ctx, a.ID, user, finding.FindingID, []int64{proof}, steps); err != nil {
		t.Fatal(err)
	}

	pb, err := d.ForAccount(a.ID).FindingVerificationPlaybook(ctx, a.ID, finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if pb == nil {
		t.Fatal("verified finding returned no playbook")
	}
	if pb.Steps != steps {
		t.Fatalf("steps = %q, want %q", pb.Steps, steps)
	}
	if pb.Summary != "Auth bypass on /admin" {
		t.Fatalf("summary = %q", pb.Summary)
	}
	if !pb.Current {
		t.Fatal("fresh verification should be current")
	}
	if len(pb.Proofs) != 1 || pb.Proofs[0].ID != proof {
		t.Fatalf("proofs = %+v, want the linked proof %d", pb.Proofs, proof)
	}
	if pb.Proofs[0].Tool != "Bash" || pb.Proofs[0].FullArtifactID == "" {
		t.Fatalf("proof ref incomplete: %+v", pb.Proofs[0])
	}

	// Evidence moves on → the stored playbook is no longer current.
	if _, err := d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1 AND account_id=$2`, finding.FindingID, a.ID); err != nil {
		t.Fatal(err)
	}
	stale, err := d.ForAccount(a.ID).FindingVerificationPlaybook(ctx, a.ID, finding.FindingID)
	if err != nil || stale == nil {
		t.Fatalf("stale playbook: %v err=%v", stale, err)
	}
	if stale.Current {
		t.Fatal("playbook should be marked not current after evidence change")
	}
}
