// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package harness

import (
	"context"
	"encoding/json"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/internal/norma/permission"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"io"
	"iter"
	"sync/atomic"
	"testing"
)

func TestStreamFailurePreservesStartedToolAndDiscardsPartialCall(t *testing.T) {
	var calls atomic.Int32
	probe := tool.Build(tool.Spec{Name: "probe", Schema: map[string]any{"type": "object", "properties": map[string]any{}}, ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true }, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
		calls.Add(1)
		return tool.Text("completed result"), nil
	}})
	model := func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, ev := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "complete", ToolName: "probe"}, {Type: llm.SEToolInputJSON, Text: "{}"}, {Type: llm.SEToolUseStart, ToolID: "partial", ToolName: "probe"}, {Type: llm.SEToolInputJSON, Text: "{\"broken\":"}} {
				if !yield(ev, nil) {
					return
				}
			}
			yield(llm.StreamEvent{}, io.ErrUnexpectedEOF)
		}
	}
	term := drain(t, QueryInput{Messages: []llm.Message{llm.UserText("fixture")}, Tools: tool.NewRegistry(probe), PermissionMode: permission.ModeBypass}, QueryDeps{CallModel: model})
	if term.Reason != ReasonModelError || calls.Load() != 1 {
		t.Fatalf("reason=%s calls=%d", term.Reason, calls.Load())
	}
	paired := false
	for _, msg := range term.Messages {
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse && block.ID == "partial" {
				t.Fatal("partial call entered history")
			}
			if block.Type == llm.BlockToolResult && block.ToolUseID == "complete" {
				paired = true
			}
		}
	}
	if !paired {
		t.Fatal("completed tool result missing from history")
	}
}
