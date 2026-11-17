package runstate

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestEvidenceDependencyRequiresReadingContext(t *testing.T) {
	s, err := New(Snapshot{ID: "fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.AfterTool("record_finding_evidence_review", nil, []byte("evidence_source_required: proof_id missing"), true)
	if s.BeforeTool("record_finding_evidence_review", json.RawMessage(`{"different":true}`)) == nil {
		t.Fatal("changed arguments bypassed missing source")
	}
	s.AfterTool("get_finding_review_context", nil, nil, false)
	if err = s.BeforeTool("record_finding_evidence_review", nil); err != nil {
		t.Fatal(err)
	}
	s.Terminal(fmt.Errorf("waiting_operator: question delivered"))
	if snap := s.Finish(context.Canceled); snap.Status != "waiting_operator" {
		t.Fatal(snap.Status)
	}
}
