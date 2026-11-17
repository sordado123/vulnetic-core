package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestBetaCatalogIsolationWithoutRLS(t *testing.T) {
	d := betaTestDB(t)
	create := func(label string) Account {
		name := fmt.Sprintf("catalog-%s-%d", label, time.Now().UnixNano())
		a, _, err := d.CreateAccountWithAdmin(name, name+"@example.test", "synthetic", func(pg *DB) error { return pg.SeedAccountAgents(map[string]string{"worker": "code default"}) })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
			d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
		})
		return a
	}
	a, b := create("a"), create("b")
	pa, pb := d.ForAccount(a.ID), d.ForAccount(b.ID)
	for _, pg := range []*DB{pa, pb} {
		if _, err := pg.CreateAgent("same_name", "Private agent", ""); err != nil {
			t.Fatal(err)
		}
		if err := pg.CreateCustomTool(&Tool{Key: "same_tool", Kind: "command", Exec: json.RawMessage(`{"command":"echo proof"}`), Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.CreateTaskCategory("Same category"); err != nil {
			t.Fatal(err)
		}
	}
	aa, err := pa.GetAgentByKey("worker")
	if err != nil || aa == nil {
		t.Fatalf("seeded worker: %v %v", aa, err)
	}
	ab, err := pb.GetAgentByKey("worker")
	if err != nil || ab == nil || aa.ID == ab.ID {
		t.Fatalf("shared worker: %v %v", ab, err)
	}
	if _, err := pa.SavePrompt(aa.ID, "account A prompt", "", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pb.SavePrompt(aa.ID, "cross-account write", "", "test"); err == nil {
		t.Fatal("foreign prompt accepted")
	}
	if text, err := pb.CurrentPrompt(aa.ID); err != nil || text != "" {
		t.Fatalf("foreign prompt leaked: %q %v", text, err)
	}
	if text, err := pb.CurrentPrompt(ab.ID); err != nil || text != "code default" {
		t.Fatalf("other account changed: %q %v", text, err)
	}
	if err := pa.SetAgentMaxTurns("worker", 7); err != nil {
		t.Fatal(err)
	}
	ab, _ = pb.GetAgentByKey("worker")
	if ab.MaxTurns == 7 {
		t.Fatal("agent budget shared")
	}
	if err := pa.DeleteCustomTool("same_tool"); err != nil {
		t.Fatal(err)
	}
	if tool, err := pb.GetTool("same_tool"); err != nil || tool == nil {
		t.Fatal("other account tool deleted")
	}
	ca, _ := pa.ListTaskCategories()
	cb, _ := pb.ListTaskCategories()
	if len(ca) != 1 || len(cb) != 1 || ca[0].ID == cb[0].ID {
		t.Fatal("categories shared")
	}
	if category, err := pb.GetTaskCategory(ca[0].ID); err != nil || category != nil {
		t.Fatalf("foreign category leaked: %v %v", category, err)
	}
	if rules, err := pa.ListInterceptRules(); err != nil || len(rules) == 0 {
		t.Fatalf("account rules missing: %v", err)
	}
}
