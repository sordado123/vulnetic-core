package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"os"
	"testing"
)

func TestBetaRetestRequiresHumanReviewOfItsOwnExecution(t *testing.T) {
	if os.Getenv("VULNETIC_PG_APP_PASSWORD") == "" {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", rlsTestAppPassword)
	}
	d := betaTestDB(t)
	a, b := betaAccount(t, d, "retest-review-a"), betaAccount(t, d, "retest-review-b")
	pa := d.ForAccount(a.ID)
	var userA, userB int64
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&userA); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, b.ID).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	task, err := pa.CreateTaskWithOptions("Review fixture", "Original evidence", TaskCreateOptions{AccountID: a.ID, UserID: userA})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	ctx := WithExecutionOwner(t.Context(), a.ID, userA)
	store := pa.Exploration(task.ExplorationID)
	recorded, err := store.RecordFinding(ctx, RecordFindingInput{TaskID: task.ID, Summary: "Original observation", Evidence: "Original response", VulnClass: "fixture", Severity: "low", Worker: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(recorded.NodeID)
	if err != nil || node.State != "candidate" || recorded.VerificationState != "candidate" {
		t.Fatal("model finding was confirmed", node, err)
	}
	addProof := func(conversationID *int64) int64 {
		t.Helper()
		proof := ExecutionProof{AccountID: a.ID, UserID: userA, ConversationID: conversationID, RunID: "fixture", Tool: "Bash", Input: json.RawMessage(`{"command":"fixture comparison"}`), Output: "Actual fixture response"}
		if conversationID == nil {
			proof.TaskID = &task.ID
		}
		if err := pa.RecordExecutionProof(ctx, proof); err != nil {
			t.Fatal(err)
		}
		proofs, err := pa.ExecutionProofs(a.ID, proof.TaskID, conversationID)
		if err != nil || len(proofs) == 0 {
			t.Fatal("proof missing", err)
		}
		return proofs[0].ID
	}
	sourceProof := addProof(nil)
	if err := pa.VerifyFinding(ctx, a.ID, userA, recorded.FindingID, []int64{sourceProof}, "Replay the original request and observe the fixture response"); err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(recorded.NodeID)
	if err != nil || node.State != "verified" {
		t.Fatal("review not reflected in graph", node, err)
	}
	r, c, _, err := pa.CreateFindingRetest(ctx, recorded.FindingID, "Compare trigger and working control")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pa.StartFindingRetest(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err = pa.RecordFindingRetestResult(ctx, c.ID, "fixed", "proposed fix", "Text alone"); err == nil {
		t.Fatal("text-only retest accepted")
	}
	proof := addProof(&c.ID)
	if err = pa.RecordFindingRetestResult(ctx, c.ID, "fixed", "Proposed fix", "Compare actual response with original trigger and normal control"); err != nil {
		t.Fatal(err)
	}
	if err = pa.FinishFindingRetest(r.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	f, err := pa.GetFinding(recorded.FindingID)
	if err != nil || f.Status == FindingFixed {
		t.Fatal("model changed triage without review", f, err)
	}
	rows, err := pa.ListFindingRetests(recorded.FindingID)
	if err != nil || len(rows) != 1 || !rows[0].ReviewRequired || rows[0].Review != nil {
		t.Fatal("proposal not identified", rows, err)
	}
	steps := "Replay the recorded trigger and normal control, then compare their actual responses"
	for _, attempt := range []struct{ account, user, proof int64 }{{a.ID, userA, sourceProof}, {a.ID, userB, proof}, {b.ID, userB, proof}} {
		if err = pa.ReviewFindingRetest(ctx, attempt.account, attempt.user, recorded.FindingID, r.ID, []int64{attempt.proof}, steps); err == nil {
			t.Fatal("foreign reviewer or execution accepted", attempt)
		}
	}
	if err = pa.ReviewFindingRetest(ctx, a.ID, userA, recorded.FindingID, r.ID, []int64{proof}, steps); err != nil {
		t.Fatal(err)
	}
	f, err = pa.GetFinding(recorded.FindingID)
	if err != nil || f.Status != FindingFixed || f.Evidence != "Original response" {
		t.Fatal("review lost evidence or triage", f, err)
	}
	rows, err = pa.ListFindingRetests(recorded.FindingID)
	if err != nil || rows[0].ReviewRequired || rows[0].Review == nil || rows[0].Review.ProofIDs[0] != proof {
		t.Fatal("review provenance missing", rows, err)
	}
	if _, err = pa.SetFindingStatus(recorded.FindingID, FindingIgnored); err != nil {
		t.Fatal(err)
	}
	if err = pa.ReviewFindingRetest(ctx, a.ID, userA, recorded.FindingID, r.ID, []int64{proof}, steps); err == nil {
		t.Fatal("review replay accepted")
	}
	f, _ = pa.GetFinding(recorded.FindingID)
	if f.Status != FindingIgnored {
		t.Fatal("review replay overwrote later triage")
	}
	stale, conv, _, err := pa.CreateFindingRetest(ctx, recorded.FindingID, "Stale source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pa.StartFindingRetest(ctx, stale.ID); err != nil {
		t.Fatal(err)
	}
	staleProof := addProof(&conv.ID)
	if err = pa.RecordFindingRetestResult(ctx, conv.ID, "reproduced", "Proposed reproduction", "Actual fixture output"); err != nil {
		t.Fatal(err)
	}
	if err = pa.FinishFindingRetest(stale.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	appDSN, err := config.PostgresAppDSN()
	if err != nil {
		t.Fatal(err)
	}
	app, err := sql.Open("pgx", appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	assertUnscopedCountAsAccount(t, app, "finding_retest_reviews", a.ID, 1)
	assertUnscopedCountAsAccount(t, app, "finding_retest_reviews", b.ID, 0)
	tx, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = setAccountGUC(tx, a.ID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO finding_retest_reviews(retest_id,account_id,user_id,steps,proof_ids) VALUES($1,$2,$3,'Wrong run',$4)`, stale.ID, a.ID, userA, "["+fmt.Sprint(sourceProof)+"]")
	tx.Rollback()
	if err == nil {
		t.Fatal("RLS accepted a review linked to another execution")
	}
	if _, err = pa.Exec(`UPDATE findings SET evidence='Changed source' WHERE id=$1`, recorded.FindingID); err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(recorded.NodeID)
	if err != nil || node.State != "candidate" {
		t.Fatal("stale graph confirmation survived", node, err)
	}
	if err = pa.ReviewFindingRetest(ctx, a.ID, userA, recorded.FindingID, stale.ID, []int64{staleProof}, steps); err == nil {
		t.Fatal("review accepted stale source")
	}
}
