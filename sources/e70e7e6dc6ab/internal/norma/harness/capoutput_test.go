// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package harness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/internal/norma/permission"
	"github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestHostRecordsFullResultBeforeModelReduction(t *testing.T) {
	full := strings.Repeat("fixture", 10000)
	registry := tool.NewRegistry()
	registry.Add(tool.Build(tool.Spec{Name: "fixture", Schema: map[string]any{"type": "object"}, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(ctx context.Context, in json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
		return tool.Text(tool.Capture(tc, full)), nil
	}}))
	recorded := ""
	ctx := tool.WithResultRecorder(t.Context(), func(id, name string, input json.RawMessage, output string, failed bool) {
		if id != "fixture-call" || name != "fixture" || failed {
			t.Error("wrong original result attribution")
		}
		recorded = output
	})
	l := &loop{ctx: ctx, in: QueryInput{Tools: registry, PermissionMode: permission.ModeBypass, MaxToolOutputChars: 100}}
	result, _ := l.execOne(ctx, llm.ContentBlock{ID: "fixture-call", Name: "fixture", Input: json.RawMessage(`{}`)}, nil)
	if recorded != full || len(result.Content[0].Text) >= len(full) {
		t.Fatal("original capture or model output limit failed")
	}
}

// The global post-tool net caps an oversized text block regardless of the tool.
func TestCapOutputCapsOversizedTextBlock(t *testing.T) {
	tc := &tool.ToolContext{MaxOutputChars: 100} // no OutputDir → head+tail truncation
	long := strings.Repeat("z", 5000)
	res := tool.Result{Content: []llm.ContentBlock{llm.TextBlock(long)}}

	out := capOutput(tc, res)
	got := out.Content[0].Text
	if len(got) >= 5000 || !strings.Contains(got, "characters truncated]") {
		t.Fatalf("capOutput did not cap oversized block: len=%d", len(got))
	}
}

// Output already within budget is passed through untouched.
func TestCapOutputLeavesSmallOutputIntact(t *testing.T) {
	tc := &tool.ToolContext{MaxOutputChars: 100}
	res := tool.Result{Content: []llm.ContentBlock{llm.TextBlock("fine")}}

	if out := capOutput(tc, res); out.Content[0].Text != "fine" {
		t.Fatalf("small output changed: %q", out.Content[0].Text)
	}
}

// Output a tool already captured (carries the spill marker) is not re-processed,
// so the net never double-truncates.
func TestCapOutputIdempotentOnAlreadyCaptured(t *testing.T) {
	tc := &tool.ToolContext{MaxOutputChars: 100}
	pre := strings.Repeat("a", 100) + "\n\n... <persisted-output>[Output too large: full 9999 bytes ... saved to x.txt </persisted-output>"
	res := tool.Result{Content: []llm.ContentBlock{llm.TextBlock(pre)}}

	if out := capOutput(tc, res); out.Content[0].Text != pre {
		t.Fatalf("capOutput re-processed already-captured output")
	}
}
