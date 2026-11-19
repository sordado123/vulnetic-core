package llmrec

import (
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"testing"
)

func TestCompactionHasDistinctProgressPhase(t *testing.T) {
	if modelRequestPhase(llm.CompletionRequest{Purpose: "compaction"}) != "compacting" {
		t.Fatal("compaction was shown as a pending user response")
	}
	if modelRequestPhase(llm.CompletionRequest{}) != "waiting_model" {
		t.Fatal("ordinary response phase changed")
	}
}
