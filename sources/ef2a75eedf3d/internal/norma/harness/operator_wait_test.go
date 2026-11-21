// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/internal/norma/permission"
	"github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/runstate"
)

func TestOperatorQuestionYieldsWithoutCancellingOrRunningLaterTools(t *testing.T) {
	state, err := runstate.New(runstate.Snapshot{ID: "operator-fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := runstate.Bind(context.Background(), state)
	ranLater := false
	ask := tool.Build(tool.Spec{Name: "ask_operator", Schema: map[string]any{"type": "object"}, Run: func(ctx context.Context, _ json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
		runstate.From(ctx).Terminal(fmt.Errorf("waiting_operator: question delivered"))
		return tool.Text("Question delivered"), nil
	}})
	later := tool.Build(tool.Spec{Name: "later", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
		ranLater = true
		return tool.Text("unexpected"), nil
	}})
	calls := 0
	deps := QueryDeps{CallModel: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		calls++
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, ev := range []llm.StreamEvent{
				{Type: llm.SEToolUseStart, ToolID: "question", ToolName: "ask_operator"},
				{Type: llm.SEToolInputJSON, Text: `{}`},
				{Type: llm.SEToolUseStart, ToolID: "deferred", ToolName: "later"},
				{Type: llm.SEToolInputJSON, Text: `{}`},
				{Type: llm.SEMessageDelta, StopReason: "tool_use"},
				{Type: llm.SEMessageStop},
			} {
				if !yield(ev, nil) {
					return
				}
			}
		}
	}}
	var terminal *Terminal
	questionReturned := false
	for ev, err := range Query(ctx, QueryInput{Messages: []llm.Message{llm.UserText("go")}, Tools: tool.NewRegistry(ask, later), PermissionMode: permission.ModeBypass}, deps) {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind == KindToolResult && ev.ToolResult.ToolUseID == "question" {
			questionReturned = !ev.ToolResult.IsError
		}
		if ev.Kind == KindResult {
			terminal = ev.Terminal
		}
	}
	if terminal == nil || terminal.Reason != ReasonWaitingOperator || terminal.Err != nil || !questionReturned || ranLater || calls != 1 || ctx.Err() != nil {
		t.Fatalf("terminal=%+v question=%v later=%v calls=%d ctx=%v", terminal, questionReturned, ranLater, calls, ctx.Err())
	}
}
