package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/internal/norma/harness"
	"github.com/sordado123/vulnetic/internal/runstate"
)

// runTrace retains the latest tool call so an interrupted run can identify the
// operation that was still in flight.
type runTrace struct {
	startedAt time.Time
	id        string
	name      string
	input     string
	at        time.Time
	pending   bool
}

func (t *runTrace) start(id, name, input string) {
	t.id, t.name, t.input, t.at, t.pending = id, name, input, time.Now(), true
}

func (t *runTrace) done(id string) {
	if id == t.id {
		t.pending = false
	}
}

var reasonHint = map[harness.TerminalReason]string{
	harness.ReasonCompleted:         "the model ended this turn normally but left no text summary; facts and assets are as recorded by this turn's tool calls",
	harness.ReasonWaitingOperator:   "the question was delivered; this Worker is paused until the operator replies, with completed results preserved",
	harness.ReasonMaxTurns:          "reached the turn cap (MaxTurns): the SDK ran the wrap-up and wrote back facts and assets; the intent is marked exhausted so the planner can continue in a different direction, rather than being treated as failed",
	harness.ReasonTimeout:           "reached this run's wall-clock budget (MaxDuration): at the deadline the in-flight tool is interrupted and the run settles in place, writing back the identified facts and assets; the intent is marked exhausted",
	harness.ReasonModelError:        "execution could not continue; use the classified error and checkpoint to identify the failed prerequisite before redispatching",
	harness.ReasonBlockingLimit:     "context length hit the hard cap and the request was intercepted before being sent; narrow the intent's granularity or compress tool output",
	harness.ReasonPromptTooLong:     "the prompt was too long and context-compaction retries were exhausted; cannot continue",
	harness.ReasonImageError:        "the current model does not support this turn's multimodal content; switch to a vision-capable model or avoid returning images from tools",
	harness.ReasonStopHookPrevented: "a Stop hook prevented this turn from ending and the run could not continue afterwards; check whether the task's Guard rules are too strict",
	harness.ReasonHookStopped:       "a tool or hook actively stopped execution, e.g. an out-of-scope target or a banned command; check the interception note on the last tool_result",
	harness.ReasonAbortedStreaming:  "the run was cancelled while the model was streaming its output",
	harness.ReasonAbortedTools:      "the run was cancelled during tool execution",
}

// terminalText renders a terminal event with no final text into a compact summary
// and a Markdown detail block.
func terminalText(ctx context.Context, term *harness.Terminal, tr *runTrace) (string, string) {
	reason := term.Reason
	aborted := reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools
	// Prompt may return ctx.Err directly without a terminal event. Preserve the
	// cancellation cause instead of falling back to an empty/unknown terminal reason.
	if reason == "" && ctx.Err() != nil {
		aborted = true
	}

	var sum string
	if aborted {
		_, short, _, ok := AbortReason(ctx)
		if !ok {
			short = "cancellation reason unavailable"
		}
		stage := "mid-execution"
		switch reason {
		case harness.ReasonAbortedStreaming:
			stage = "the model output stage"
		case harness.ReasonAbortedTools:
			stage = "the tool execution stage"
		}
		sum = "(run interrupted: " + short + "; stopped during " + stage + progressSuffix(term, tr) + ", unfinished)"
	} else if reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout {
		sum = "(run budget cap reached (" + string(reason) + "); wrap-up wrote back facts" + progressSuffix(term, tr) + "; no text summary this run)"
	} else {
		hint := terminalReasonHint(reason)
		sum = "(no text summary; terminal state " + terminalReasonLabel(reason) + ": " + firstLine(hint, 80) + ")"
	}

	// Enrich the reason-specific summary with recovery guidance rather than
	// replacing it: the cause (why the run stopped) must stay in the first line.
	// Overwriting here dropped the cause for every errored or output-less run —
	// aborts always carry ctx.Canceled and a budget cap writes no text — which is
	// exactly what the agent needs to see.
	if term.Err != nil {
		_, message, recovery := runstate.Classify(term.Err)
		sum += " " + message + " " + recovery
	} else if term.Text == "" {
		sum += " Review the recorded tool results and checkpoint before continuing."
	}
	if state := runstate.From(ctx); state != nil {
		snapshot := state.Snapshot()
		sum += fmt.Sprintf(" %d tool calls returned (%d errors); %d unfinished.", snapshot.CompletedTools, snapshot.FailedTools, snapshot.PendingTools)
	}
	var b strings.Builder
	b.WriteString(sum)
	b.WriteString("\n\n")
	displayReason := terminalReasonLabel(reason)
	fmt.Fprintf(&b, "- **Terminal state**: `%s` - %s\n", displayReason, terminalReasonHint(reason))
	if aborted {
		code, _, why, ok := AbortReason(ctx)
		if ok {
			fmt.Fprintf(&b, "- **Interruption cause** (`%s`): %s\n", code, why)
		} else {
			b.WriteString("- **Interruption cause**: unavailable; the cancelling side may not have attached a named cause via context.WithCancelCause\n")
		}
	}
	if term.Err != nil {
		fmt.Fprintf(&b, "- **Underlying error**: `%v`\n", term.Err)
	}
	if aborted && strings.TrimSpace(term.Text) != "" {
		b.WriteString("- **Partial output generated before cancellation**:\n\n")
		b.WriteString(term.Text)
		b.WriteString("\n\n")
	}
	if term.Turns > 0 {
		fmt.Fprintf(&b, "- **Executed**: %d model turns\n", term.Turns)
	}
	if !tr.startedAt.IsZero() {
		fmt.Fprintf(&b, "- **Run duration**: %s\n", roundDur(time.Since(tr.startedAt)))
	}
	if u := term.Usage; u.InputTokens+u.OutputTokens+u.CacheReadTokens+u.CacheWriteTokens > 0 {
		fmt.Fprintf(&b, "- **Total tokens**: input %d / output %d / cache read %d / cache write %d\n",
			u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	if tr.name == "" {
		b.WriteString("- **Tool calls**: the run ended before any tool call was made\n")
	} else if tr.pending {
		fmt.Fprintf(&b, "- **Tool in flight at interruption**: `%s` (ran for %s, **no result returned**)\n\n  ```json\n  %s\n  ```\n",
			tr.name, roundDur(time.Since(tr.at)), firstLine(tr.input, 300))
	} else {
		fmt.Fprintf(&b, "- **Last tool before interruption**: `%s` (returned normally)\n", tr.name)
	}
	return sum, b.String()
}

func terminalReasonLabel(reason harness.TerminalReason) string {
	if reason == "" {
		return "context_canceled"
	}
	return string(reason)
}

func terminalReasonHint(reason harness.TerminalReason) string {
	if hint := reasonHint[reason]; hint != "" {
		return hint
	}
	if reason == "" {
		return "the run's context was cancelled, but no Terminal event was produced underneath"
	}
	return "unknown terminal state; harness may have added a TerminalReason — please add it to reasonHint"
}

func progressSuffix(term *harness.Terminal, tr *runTrace) string {
	var parts []string
	if term.Turns > 0 {
		parts = append(parts, fmt.Sprintf("%d turns", term.Turns))
	}
	if !tr.startedAt.IsZero() {
		parts = append(parts, roundDur(time.Since(tr.startedAt)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", ran for " + strings.Join(parts, " / ")
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
