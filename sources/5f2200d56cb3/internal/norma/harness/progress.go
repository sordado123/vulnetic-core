package harness

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/sordado123/vulnetic/internal/norma/llm"
)

type progressMonitor struct {
	fingerprint [32]byte
	repeats     int
}

// Consultative only: identical calls may be intentional polling. Never cancel a worker.
func (l *loop) observeProgress(calls, results []llm.ContentBlock) {
	var normalized []any
	for _, call := range calls {
		if call.Type != llm.BlockToolUse {
			continue
		}
		for _, result := range results {
			if result.ToolUseID == call.ID {
				normalized = append(normalized, []any{call.Name, string(call.Input), result.IsError, result.Content})
				break
			}
		}
	}
	if len(normalized) == 0 {
		return
	}
	raw, _ := json.Marshal(normalized)
	fingerprint := sha256.Sum256(raw)
	if fingerprint == l.progressMonitor.fingerprint {
		l.progressMonitor.repeats++
	} else {
		l.progressMonitor = progressMonitor{fingerprint, 1}
	}
	if l.progressMonitor.repeats != 3 && l.progressMonitor.repeats != 6 {
		return
	}
	note := "Progress advisory: identical tool arguments and results repeated across several turns. Check recorded work and prerequisites before repeating. Continue legitimate polling or unfinished validation when needed; otherwise change the approach or record the blocker. This advisory imposes no execution limit and grants no permissions."
	msg := llm.UserText(note)
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
	l.emit(Event{Kind: KindProgress, Text: "Repeated unchanged tool results; progress advisory recorded. Execution continues."})
}
