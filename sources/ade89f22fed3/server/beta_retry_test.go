package server

import (
	"fmt"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/llmpool"
	"testing"
	"time"
)

func TestBetaRetryAndHealthPoliciesBelongToAccount(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	accounts := make([]int64, 2)
	profiles := make([]int64, 2)
	for i := range accounts {
		name := fmt.Sprintf("retry-owner-%d-%d", time.Now().UnixNano(), i)
		account, _, err := pg.CreateAccountWithAdmin(name, name+"@example.test", "unused-test-hash", func(scoped *db.DB) error {
			return scoped.SeedAccountAgents(map[string]string{"worker": "fixture"})
		})
		if err != nil {
			t.Fatal(err)
		}
		accounts[i] = account.ID
		defer pg.Exec(`DELETE FROM accounts WHERE id=$1`, account.ID)
		defer pg.Exec(`DELETE FROM users WHERE account_id=$1`, account.ID)
		scoped := pg.ForAccount(account.ID)
		profiles[i], err = scoped.SaveProfile(&db.LLMProfile{AccountID: account.ID, Name: "same-name", Format: "openai", Model: "test", APIKey: "fixture-only"})
		if err != nil {
			t.Fatal(err)
		}
		policy := db.LLMRetryPolicy{Empty: db.RetryRule{Attempts: i + 1}, Breaker: db.RetryRule{Attempts: i + 1, IntervalMS: 1000 * (i + 1)}}
		if err := scoped.SetLLMRetryPolicy(policy); err != nil {
			t.Fatal(err)
		}
		if err := scoped.SetAgentLLMProfile("worker", &profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	server := &Server{m: &Manager{pg: pg}, llmHealth: llmpool.NewRegistry(nil, nil), provByProfile: map[int64]*provEntry{}, llmOn: true}
	engine := &Engine{m: server.m}
	server.applyAccountHealthPolicy(accounts[0])
	server.applyAccountHealthPolicy(accounts[1])
	for i, account := range accounts {
		if got := engine.emptyTurnNudgeLimit(account); got != i+1 {
			t.Fatalf("account %d: got %d", i, got)
		}
	}
	if !server.llmHealth.Trip(profiles[0], "429", false) {
		t.Fatal("first account policy not applied")
	}
	if server.llmHealth.Trip(profiles[1], "429", false) {
		t.Fatal("second account inherited first account policy")
	}
	if !server.llmHealth.Trip(profiles[1], "429", false) {
		t.Fatal("second account policy not applied")
	}
	if err := pg.ForAccount(accounts[0]).SetLLMRetryPolicy(db.LLMRetryPolicy{Empty: db.RetryRule{Attempts: -1}, Breaker: db.RetryRule{Attempts: -1}}); err != nil {
		t.Fatal(err)
	}
	server.applyAccountHealthPolicy(accounts[0])
	server.llmHealth.Reset(profiles[0])
	if engine.emptyTurnNudgeLimit(accounts[0]) != 0 || engine.emptyTurnNudgeLimit(accounts[1]) != 2 {
		t.Fatal("saving one account changed another")
	}
	if server.llmHealth.Trip(profiles[0], "429", false) {
		t.Fatal("updated policy not applied")
	}
	if !server.llmHealth.Get(profiles[1]).Open() {
		t.Fatal("updating one account cleared another's state")
	}
	for i, account := range accounts {
		resolved, err := server.resolveTaskRoleLLM(&Task{AccountID: account}, "worker")
		if err != nil || !resolved.Available || resolved.ProfileID == nil || *resolved.ProfileID != profiles[i] {
			t.Fatal("diagnostics did not resolve the account's own agent binding", resolved, err)
		}
		resolved, err = server.resolveTaskRoleLLM(&Task{AccountID: account}, "planner")
		if err != nil || resolved.Available || resolved.ProfileID != nil || resolved.Model != "" {
			t.Fatal("diagnostics exposed global configuration without an own task chain", resolved, err)
		}
		foreign := profiles[1-i]
		resolved, err = server.resolveTaskRoleLLM(&Task{AccountID: account, LLMProfileIDs: []int64{foreign}, ActiveLLMProfileID: &foreign}, "planner")
		if err != nil || resolved.Available || resolved.ProfileID != nil {
			t.Fatal("diagnostics exposed a foreign historical profile reference", resolved, err)
		}
	}
	if _, err := server.resolveTaskRoleLLM(&Task{}, "planner"); err == nil {
		t.Fatal("missing account accepted by diagnostics")
	}
}
