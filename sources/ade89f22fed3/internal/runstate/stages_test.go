package runstate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStagesAreBoundedAndIsolated(t *testing.T) {
	s, err := New(Snapshot{ID: "fixture", ExecutorID: 13}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithOperation(Bind(context.Background(), s), "call-fixture")
	for i := 0; i < 100; i++ {
		RecordStage(ctx, "dns", time.Now().Add(-time.Millisecond), false)
	}
	RecordStage(ctx, "https://secret@example.test/", time.Now(), true)
	value := s.Snapshot()
	if len(value.Stages) != 32 || value.Stages[0].OperationID != "call-fixture" || value.TokenLimit != 0 {
		t.Fatal(value)
	}
	value.Stages[0].Name = "mutated"
	if s.Snapshot().Stages[0].Name != "dns" {
		t.Fatal("snapshot shares mutable stage slice")
	}
	raw, _ := json.Marshal(s.Snapshot())
	if strings.Contains(string(raw), "secret") {
		t.Fatal("unbounded metadata accepted")
	}
	RecordStage(context.Background(), "dns", time.Now(), false)
}
