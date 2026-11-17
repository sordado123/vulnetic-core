package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func betaTestDB(t *testing.T) *DB {
	t.Helper()
	dsn, _, err := DSN()
	if err == nil {
		var d *DB
		d, err = Open(dsn)
		if err == nil {
			t.Cleanup(func() { d.Close() })
			return d
		}
	}
	if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
		t.Fatalf("required PostgreSQL verification unavailable: %v", err)
	}
	t.Skipf("PostgreSQL verification pending: %v", err)
	return nil
}

func TestBetaPilotAdmissionIsAtomic(t *testing.T) {
	d := betaTestDB(t)
	var before int
	if err := d.QueryRow(`SELECT COUNT(DISTINCT account_id) FROM users`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	type admission struct {
		account Account
		err     error
	}
	results := make(chan admission, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			name := fmt.Sprintf("pilot-%d-%d", time.Now().UnixNano(), i)
			a, _, err := d.CreatePilotAccountWithAdmin(name, name+"@example.test", "synthetic-hash")
			results <- admission{a, err}
		}(i)
	}
	successes := 0
	for i := 0; i < 8; i++ {
		r := <-results
		if r.err == nil {
			successes++
			// Do not release capacity until every concurrent attempt has finished.
			defer func(id int64) {
				d.Exec(`DELETE FROM users WHERE account_id=$1`, id)
				d.Exec(`DELETE FROM accounts WHERE id=$1`, id)
			}(r.account.ID)
		} else if !errors.Is(r.err, ErrPilotFull) {
			t.Errorf("unexpected admission failure: %v", r.err)
		}
	}
	want := 5 - before
	if want < 0 {
		want = 0
	}
	if successes != want {
		t.Fatalf("concurrent pilot admissions=%d, want %d", successes, want)
	}
}

func betaAccount(t *testing.T, d *DB, label string) Account {
	t.Helper()
	unique := fmt.Sprintf("beta-%s-%d", label, time.Now().UnixNano())
	a, _, err := d.CreateAccountWithAdmin(unique, unique+"@example.test", "not-a-real-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM scheduled_task_actions WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM intercept_pending WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM conversations WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM tasks WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM llm_profiles WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
		d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
	})
	return a
}

func TestBetaApprovalOwnership(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "a")
	b := betaAccount(t, d, "b")
	c, err := d.CreateConversation(a.ID, "auto", "approval proof", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.CreateInterceptPending(0, c.ID, "", "auto", "Bash", []byte(`{}`), "proof")
	if err != nil {
		t.Fatal(err)
	}
	for account, want := range map[int64]bool{a.ID: true, b.ID: false, 0: false} {
		got, err := d.OwnsIntercept(context.Background(), account, id)
		if err != nil || got != want {
			t.Fatalf("account %d: %v %v", account, got, err)
		}
	}
	if resolved, err := d.ResolveInterceptForAccount(b.ID, id, "allowed", "allow", "wrong account"); err != nil || resolved {
		t.Fatalf("cross-account decision: %v %v", resolved, err)
	}
	items, err := d.ListPendingInterceptsForAccount(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == id {
			t.Fatal("pending approval leaked")
		}
	}
	if resolved, err := d.ResolveInterceptForAccount(a.ID, id, "denied", "deny", "own account"); err != nil || !resolved {
		t.Fatalf("own decision: %v %v", resolved, err)
	}
}

func TestBetaScheduledPauseOwnership(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "a")
	b := betaAccount(t, d, "b")
	p, err := d.CreateScheduledPause(a.ID, "", time.Now().Add(time.Hour), "proof", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CancelScheduledPause(b.ID, p.ID); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListScheduledPauses(a.ID)
	if err != nil || len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("wrong account cancelled schedule: %v %v", list, err)
	}
	other, err := d.ListScheduledPauses(b.ID)
	if err != nil || len(other) != 0 {
		t.Fatalf("schedule leaked: %v %v", other, err)
	}
	if _, err := d.CreateScheduledPause(0, "", time.Now(), "", "test"); err == nil {
		t.Fatal("schedule without owner accepted")
	}
}

func TestBetaAccountLLMDefaults(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "a")
	b := betaAccount(t, d, "b")
	create := func(account int64) int64 {
		id, err := d.SaveProfile(&LLMProfile{AccountID: account, Name: fmt.Sprintf("beta-profile-%d", account), Format: "openai", Model: "test", APIKey: "synthetic-test-key"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	pa, pb := create(a.ID), create(b.ID)
	if err := d.SetActiveProfileForAccount(a.ID, pa); err != nil {
		t.Fatal(err)
	}
	if err := d.SetActiveProfileForAccount(b.ID, pb); err != nil {
		t.Fatal(err)
	}
	if err := d.SetActiveProfileForAccount(b.ID, pa); err == nil {
		t.Fatal("cross-account activation accepted")
	}
	for account, want := range map[int64]int64{a.ID: pa, b.ID: pb} {
		profile, err := d.ActiveProfileForAccount(account)
		if err != nil || profile == nil || profile.ID != want {
			t.Fatalf("account default changed: %v %v", profile, err)
		}
	}
}
