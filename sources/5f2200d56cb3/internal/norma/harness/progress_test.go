package harness

import (
	"encoding/json"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"testing"
)

func TestProgressAdvisoryDoesNotStopOrCountDifferentResults(t *testing.T) {
	events := 0
	l := &loop{yield: func(Event, error) bool { events++; return true }}
	for i := 0; i < 8; i++ {
		l.observeProgress([]llm.ContentBlock{{Type: llm.BlockToolUse, ID: "call", Name: "Bash", Input: json.RawMessage(`{"command":"fixture"}`)}}, []llm.ContentBlock{llm.ToolResultText("call", "unchanged", false)})
	}
	if events != 2 || len(l.messages) != 2 || l.turnCount != 0 || l.settling {
		t.Fatalf("advisory changed execution: %+v", l)
	}
	l.observeProgress([]llm.ContentBlock{{Type: llm.BlockToolUse, ID: "new", Name: "Bash", Input: json.RawMessage(`{"command":"fixture"}`)}}, []llm.ContentBlock{llm.ToolResultText("new", "new observation", false)})
	if l.progressMonitor.repeats != 1 {
		t.Fatal("new observation treated as loop")
	}
}
