package db

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/internal/runstate"
	"testing"
)

func TestExecutionRunOwnershipAndLedgerAttribution(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "run-owner-a")
	b := betaAccount(t, d, "run-owner-b")
	c, err := d.ForAccount(a.ID).CreateConversation(a.ID, "reporter", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	t.Cleanup(func() {
		d.Exec(`DELETE FROM llm_usage WHERE run_id=$1`, id)
		d.Exec(`DELETE FROM execution_runs WHERE id=$1`, id)
	})
	snapshot := runstate.Snapshot{ID: id, ConversationID: c.ID, Status: "running"}
	if err = d.ForAccount(b.ID).SaveExecutionRun(b.ID, snapshot); err == nil {
		t.Fatal("cross-account conversation linked")
	}
	if err = d.ForAccount(a.ID).SaveExecutionRun(a.ID, snapshot); err != nil {
		t.Fatal(err)
	}
	if err = d.ForAccount(b.ID).SaveExecutionRun(a.ID, snapshot); err == nil {
		t.Fatal("scoped store changed account")
	}
	other, err := d.ForAccount(b.ID).ExecutionRuns(b.ID, 0, c.ID)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-account metadata exposed: %v", err)
	}
	usage := &LLMUsage{AccountID: a.ID, RunID: id, ConversationID: c.ID, Model: "synthetic", InputTokens: 10, OutputTokens: 2}
	if err = d.ForAccount(a.ID).InsertLLMUsage(usage); err != nil {
		t.Fatal(err)
	}
	bad := &LLMUsage{AccountID: b.ID, RunID: id, ConversationID: c.ID, Model: "synthetic"}
	if err = d.ForAccount(b.ID).InsertLLMUsage(bad); err == nil {
		t.Fatal("cross-account usage association accepted")
	}
}

func TestExecutorLookupContextAndExplicitOwner(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "lookup-a")
	b := betaAccount(t, d, "lookup-b")
	if _, err := d.ForAccount(a.ID).GetSSHTargetContext(t.Context(), b.ID, 1); !errors.Is(err, ErrSSHTargetNotFound) {
		t.Fatal("explicit owner not enforced", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := d.ForAccount(a.ID).GetSSHTargetContext(ctx, a.ID, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("lookup ignored cancellation", err)
	}
}
