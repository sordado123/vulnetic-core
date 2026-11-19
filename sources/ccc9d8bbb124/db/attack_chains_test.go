package db

import (
	"bytes"
	"testing"
)

// RecordAttackChain + AttackChains is the #24 round trip: the agent declares an
// ordered chain over this task's own findings, and it reads back with the steps in
// order resolved to each finding's title. A step that points outside the task must
// be rejected, not stored. Needs Postgres (betaTestDB); skipped without a DB.
func TestAttackChainRoundTrip(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "chain-a")
	d.ConfigureVault(bytes.Repeat([]byte{81}, 32), true)
	ctx := t.Context()
	var user int64
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM attack_chains WHERE account_id=$1`, a.ID)
	})
	target, err := d.ForAccount(a.ID).CreateExecutionAgent(ctx, a.ID, "chain lab", 3600, bytes.Repeat([]byte{73}, 32), []byte("encrypted"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, bytes.Repeat([]byte{73}, 32), bytes.Repeat([]byte{74}, 32), "fixture-host", "fixture"); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("chain fixture", "owned lab", TaskCreateOptions{AccountID: a.ID, UserID: user, SSHTargetID: &target.ID})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := d.ForAccount(a.ID).Assets().UpsertHTTPService(UpsertHTTPServiceReq{URL: "http://fixture.invalid", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	exp := d.ForAccount(a.ID).Exploration(task.ExplorationID)
	octx := WithExecutionOwner(ctx, a.ID, user)
	f1, err := exp.RecordFinding(octx, RecordFindingInput{TaskID: task.ID, Summary: "SSRF in webhook", Evidence: "reached 169.254.169.254", VulnClass: "A10", Severity: "medium", Worker: "fixture", AssetIDs: []int64{asset}})
	if err != nil {
		t.Fatal(err)
	}
	f2, err := exp.RecordFinding(octx, RecordFindingInput{TaskID: task.ID, Summary: "Cloud creds via metadata", Evidence: "pulled role credentials", VulnClass: "A10", Severity: "high", Worker: "fixture", AssetIDs: []int64{asset}})
	if err != nil {
		t.Fatal(err)
	}

	// A single step is not a chain.
	if _, err := exp.RecordAttackChain(octx, AttackChainInput{TaskID: task.ID, Title: "x", Narrative: "y", Severity: "high", Steps: []AttackChainStepInput{{FindingID: f1.FindingID}}}); err == nil {
		t.Fatal("one-step chain accepted")
	}
	// A step outside the task cannot be referenced.
	if _, err := exp.RecordAttackChain(octx, AttackChainInput{TaskID: task.ID, Title: "x", Narrative: "y", Severity: "high", Steps: []AttackChainStepInput{{FindingID: f1.FindingID}, {FindingID: 99999999}}}); err == nil {
		t.Fatal("chain with a foreign finding accepted")
	}

	id, err := exp.RecordAttackChain(octx, AttackChainInput{
		TaskID: task.ID, Title: "SSRF to cloud takeover", Severity: "critical",
		Narrative: "The webhook SSRF reaches the metadata endpoint, which yields role credentials, escalating two mediums into a full account takeover.",
		Steps: []AttackChainStepInput{
			{FindingID: f1.FindingID, Rationale: "reach the internal metadata service"},
			{FindingID: f2.FindingID, Rationale: "exchange it for cloud role credentials"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Fatalf("chain id = %d", id)
	}

	chains, err := d.ForAccount(a.ID).AttackChains(ctx, a.ID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("chains = %d, want 1", len(chains))
	}
	c := chains[0]
	if c.Title != "SSRF to cloud takeover" || c.Severity != "critical" {
		t.Fatalf("chain header wrong: %+v", c)
	}
	if len(c.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(c.Steps))
	}
	if c.Steps[0].Position != 0 || c.Steps[0].FindingID != f1.FindingID || c.Steps[1].FindingID != f2.FindingID {
		t.Fatalf("steps out of order: %+v", c.Steps)
	}
	if c.Steps[0].Summary != "SSRF in webhook" || c.Steps[1].Severity != "high" {
		t.Fatalf("steps not resolved to findings: %+v", c.Steps)
	}

	// Another account sees no chains for this task.
	b := betaAccount(t, d, "chain-b")
	if other, err := d.ForAccount(b.ID).AttackChains(ctx, b.ID, task.ID); err != nil || len(other) != 0 {
		t.Fatalf("cross-account chains leaked: %d err=%v", len(other), err)
	}
}
