package runstate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunWithoutTokenCapCheckpointAndPersistence(t *testing.T) {
	t.Setenv("VULNETIC_RUN_TOKEN_LIMIT", "2000000")
	var saved Snapshot
	s, err := New(Snapshot{ID: "fixture", TokenLimit: 2000000}, func(v Snapshot) error { saved = v; return nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Observe("tool_use", false)
	s.ToolReference("tool_use", "tool-1", "Bash")
	s.AddUsage(21000000, 1000)
	if err = s.BeforeCall(); err != nil {
		t.Fatal("token usage blocked a call:", err)
	}
	if err = s.BeforeTool("Bash", []byte(`{}`)); err != nil {
		t.Fatal("token usage blocked a tool:", err)
	}
	s.Phase("finalizing")
	end := s.Finish(nil)
	if end.Code != "" || saved.Status != "completed" || end.PendingTools != 1 || end.Checkpoint == "" || end.Tokens != 21001000 || end.TokenLimit != 0 || saved.TokenLimit != 0 {
		t.Fatalf("bad checkpoint: %+v", end)
	}
	if err = s.BeforeCall(); err == nil {
		t.Fatal("closed execution allowed a call")
	}
	if end.FinishedAt == nil || end.StartedAt.After(*end.FinishedAt) {
		t.Fatal("invalid lifecycle times")
	}
}
func TestFailureCooldownAndRecovery(t *testing.T) {
	s, _ := New(Snapshot{ID: "fixture"}, nil)
	s.AfterTool("list_task_credentials", []byte(`{}`), []byte(`only available inside a task`), true)
	if err := s.BeforeTool("list_task_credentials", []byte("{ }")); err == nil {
		t.Fatal("unchanged failure retried")
	}
	s.AfterTool("update_task", nil, nil, false)
	if err := s.BeforeTool("list_task_credentials", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	s.AfterTool("Bash", nil, []byte(`port closed`), true)
	if err := s.BeforeTool("Bash", nil); err != nil {
		t.Fatal("ordinary negative result disabled tool")
	}
	s.failures[fingerprint("test", nil)] = time.Now().Add(-2 * time.Minute)
	if err := s.BeforeTool("test", nil); err != nil {
		t.Fatal("prerequisite was never rechecked")
	}
}
func TestClassificationAndFailClosed(t *testing.T) {
	for _, v := range []struct{ message, code string }{{"policy_denied: protected target", "platform_policy"}, {"select a verified VPS", "executor_unavailable"}, {"invalid schema", "tool_schema"}, {"status 401", "provider_auth"}, {"status 429", "rate_limit"}, {"status 503", "provider_unavailable"}, {"deadline exceeded", "timeout"}} {
		code, _, recovery := Classify(errors.New(v.message))
		if code != v.code || recovery == "" {
			t.Errorf("%q: %s", v.message, code)
		}
	}
	code, _, _ := Classify(context.Canceled)
	if code != "cancelled" {
		t.Fatal(code)
	}
	s, err := New(Snapshot{ID: "fixture"}, func(Snapshot) error { return errors.New("storage unavailable") })
	if err == nil || s != nil {
		t.Fatal("allowed untracked execution")
	}
}
