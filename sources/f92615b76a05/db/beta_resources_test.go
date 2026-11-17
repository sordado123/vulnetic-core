package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestBetaResourcesAndProofOwnershipWithoutRLS(t *testing.T) {
	d := betaTestDB(t)
	create := func(label string) (Account, *DB) {
		name := fmt.Sprintf("resources-%s-%d", label, time.Now().UnixNano())
		a, _, err := d.CreateAccountWithAdmin(name, name+"@example.test", "synthetic")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
			d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
		})
		return a, d.ForAccount(a.ID)
	}
	a, pa := create("a")
	b, pb := create("b")
	var userA, userB int64
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, a.ID).Scan(&userA); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT id FROM users WHERE account_id=$1`, b.ID).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	profile := func(pg *DB) int64 {
		id, err := pg.SaveProfile(&LLMProfile{Name: "Same name", Format: "openai", Model: "fixture", APIKey: "synthetic"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	profileA, profileB := profile(pa), profile(pb)
	if p, err := pb.ProfileByID(profileA); err != nil || p != nil {
		t.Fatalf("foreign profile: %v %v", p, err)
	}
	for _, pg := range []*DB{pa, pb} {
		profiles, err := pg.PoolProfiles()
		if err != nil || len(profiles) != 1 {
			t.Fatalf("pool: %v %v", profiles, err)
		}
	}
	conv, err := pa.CreateConversation(a.ID, "auto", "Private conversation", &profileA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pa.CreateConversation(a.ID, "auto", "Cross account pin", &profileB); err == nil {
		t.Fatal("foreign profile was accepted")
	}
	if c, err := pb.GetConversation(conv.ID); err != nil || c != nil {
		t.Fatalf("foreign conversation: %v %v", c, err)
	}
	if _, err = pb.AppendConvActivity(conv.ID, Activity{Kind: "user", Summary: "tamper"}); err == nil {
		t.Fatal("foreign activity write")
	}
	if err = pb.DeleteConversation(conv.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := pa.GetConversation(conv.ID); c == nil {
		t.Fatal("foreign delete removed conversation")
	}
	if _, err = pb.DeleteConversations([]int64{conv.ID}); err != nil {
		t.Fatal(err)
	}
	if rows, err := pb.ListConversations(); err != nil || len(rows) != 0 {
		t.Fatalf("conversation list: %v %v", rows, err)
	}
	for _, pg := range []*DB{pa, pb} {
		if _, err = pg.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: "same-fixture.example"}); err != nil {
			t.Fatal(err)
		}
	}
	if rows, err := pa.Assets().QueryByType("root_domain", 100, 0); err != nil || len(rows) != 1 {
		t.Fatalf("asset scope: %v %v", rows, err)
	}
	if err = d.InsertLLMRecord(&LLMRecord{AccountID: a.ID, Model: "secret-model-a", SessionID: "isolated"}); err != nil {
		t.Fatal(err)
	}
	if rows, total, err := pb.ListLLMRecords("", "", "", 0, 100); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("record scope: %v %v", rows, err)
	}
	if err = d.InsertLLMUsage(&LLMUsage{AccountID: a.ID, Model: "fixture", ProfileName: "Same name", InputTokens: 123}); err != nil {
		t.Fatal(err)
	}
	if rows, err := pb.UsageByProfile(); err != nil || len(rows) != 0 {
		t.Fatalf("usage scope: %v %v", rows, err)
	}
	if err = pa.RecordAudit(a.ID, 99, "POST", "/api/fixture", 200); err != nil {
		t.Fatal(err)
	}
	if rows, err := pb.ListAudit(b.ID); err != nil || len(rows) != 0 {
		t.Fatalf("audit scope: %v %v", rows, err)
	}
	task, err := pa.CreateTaskWithOptions("Authorized fixture", "Proof binding", TaskCreateOptions{AccountID: a.ID, UserID: userA})
	if err != nil {
		t.Fatal(err)
	}
	other, err := pb.CreateTaskWithOptions("Other fixture", "Foreign proof", TaskCreateOptions{AccountID: b.ID})
	if err != nil {
		t.Fatal(err)
	}
	if task.UserID != userA {
		t.Fatal("task actor was lost")
	}
	if _, err = pa.CreateTaskWithOptions("Foreign actor", "Reject", TaskCreateOptions{AccountID: a.ID, UserID: userB}); err == nil {
		t.Fatal("foreign task actor accepted")
	}
	if _, err = pa.CreateTaskWithOptions("Foreign profile", "Reject", TaskCreateOptions{AccountID: a.ID, LLMProfileIDs: []int64{profileB}}); err == nil {
		t.Fatal("foreign task profile accepted")
	}
	if _, err = pa.CreateConversation(a.ID, "auto", "Foreign actor", nil, userB); err == nil {
		t.Fatal("foreign conversation actor accepted")
	}
	findingID, err := pa.AddFinding(task.ID, 0, "fixture", "Candidate", "low", "observed behavior", "candidate evidence", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := pa.GetFinding(findingID)
	if err != nil || finding.VerificationState != "candidate" {
		t.Fatalf("candidate: %v %v", finding, err)
	}
	if err = pa.VerifyFinding(context.Background(), a.ID, userA, findingID, nil, "Reproduce with the fixture request"); err == nil {
		t.Fatal("text-only confirmation")
	}
	for _, proof := range []ExecutionProof{{AccountID: a.ID, UserID: userA, TaskID: &task.ID, RunID: "run-a", Tool: "Bash", Input: json.RawMessage(`{"command":"echo proof"}`), Output: "actual execution"}, {AccountID: b.ID, TaskID: &other.ID, RunID: "run-b", Tool: "Bash", Input: json.RawMessage(`{"command":"echo foreign"}`), Output: "other account"}} {
		if err = d.RecordExecutionProof(context.Background(), proof); err != nil {
			t.Fatal(err)
		}
	}
	proofsA, err := pa.ExecutionProofs(a.ID, &task.ID, nil)
	if err != nil || len(proofsA) != 1 {
		t.Fatalf("proof list: %v %v", proofsA, err)
	}
	proofsB, err := pb.ExecutionProofs(b.ID, &other.ID, nil)
	if err != nil || len(proofsB) != 1 {
		t.Fatalf("foreign proof list: %v %v", proofsB, err)
	}
	if err = pa.VerifyFinding(context.Background(), a.ID, userA, findingID, []int64{proofsB[0].ID}, "Reproduce with a foreign proof"); err == nil {
		t.Fatal("foreign proof accepted")
	}
	if err = pa.VerifyFinding(context.Background(), a.ID, userA, findingID, []int64{proofsA[0].ID}, "Run the recorded request and compare the actual response"); err != nil {
		t.Fatal(err)
	}
	if err = pa.VerifyFinding(context.Background(), a.ID, userB, findingID, []int64{proofsA[0].ID}, "Invalid reviewer must be rejected"); err == nil {
		t.Fatal("foreign reviewer accepted")
	}
	finding, err = pa.GetFinding(findingID)
	if err != nil || finding.VerificationState != "verified" {
		t.Fatalf("verified: %v %v", finding, err)
	}
	if _, err = d.Exec(`UPDATE findings SET evidence='changed' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	finding, err = pa.GetFinding(findingID)
	if err != nil || finding.VerificationState != "candidate" {
		t.Fatalf("stale verification: %v %v", finding, err)
	}
}
