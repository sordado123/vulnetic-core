package compaction

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/internal/norma/transcript"
)

// ContextMemory has no global index: the host binds one account store and session.
type ContextMemory struct {
	accountID int64
	store     *transcript.Store
	session   func() string
	mu        sync.Mutex
	requested bool
	status    map[string]any
}

type contextMemoryKey struct{}

func WithContextMemory(ctx context.Context, memory *ContextMemory) context.Context {
	return context.WithValue(ctx, contextMemoryKey{}, memory)
}
func MemoryFromContext(ctx context.Context) *ContextMemory {
	value, _ := ctx.Value(contextMemoryKey{}).(*ContextMemory)
	return value
}
func (m *ContextMemory) AccountID() int64 { return m.accountID }

func (c *Compactor) BindContextMemory(accountID int64, store *transcript.Store, session func() string) {
	if accountID > 0 && store != nil && store.Strict() && session != nil {
		c.memory = &ContextMemory{accountID: accountID, store: store, session: session, status: map[string]any{}}
	}
}
func (c *Compactor) ContextMemory() *ContextMemory { return c.memory }

func (m *ContextMemory) RequestCompression() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requested = true
}
func (m *ContextMemory) takeRequest() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	requested := m.requested
	m.requested = false
	return requested
}
func (m *ContextMemory) update(window, before, after, messages, failures int, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = map[string]any{"context_window": window, "estimated_tokens_before": before, "estimated_tokens_after": after, "messages_in_request": messages, "consecutive_summary_failures": failures, "last_outcome": outcome}
}
func (m *ContextMemory) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{"session_id": m.session(), "compression_requested": m.requested, "originals_preserved": true, "untrusted": true, "note": "Estimates cover messages/tool schemas, not a billing total. Search and restore access only this persisted session; they never replay tools."}
	for key, value := range m.status {
		out[key] = value
	}
	return out
}

func recordText(record transcript.Record) string {
	var text strings.Builder
	var blocks func([]llm.ContentBlock)
	blocks = func(content []llm.ContentBlock) {
		for _, block := range content {
			switch block.Type {
			case llm.BlockText:
				text.WriteString(block.Text)
				text.WriteByte('\n')
			case llm.BlockToolUse:
				text.WriteString("[tool " + block.Name + " id=" + block.ID + "]\n")
				text.Write(block.Input)
				text.WriteByte('\n')
			case llm.BlockToolResult:
				text.WriteString(fmt.Sprintf("[tool result id=%s failed=%t]\n", block.ToolUseID, block.IsError))
				blocks(block.Content)
			}
		}
	}
	blocks(record.Message.Content)
	return text.String()
}

// Stay below the tool-result byte cap, including JSON escapes and UTF-8 expansion.
func contextExcerpt(runes []rune, start, maxChars, maxBytes int) (string, int) {
	end := min(start+maxChars, len(runes))
	for {
		text := string(runes[start:end])
		encoded, _ := json.Marshal(text)
		if len(encoded) <= maxBytes || end == start {
			return text, end
		}
		end = start + (end-start)*3/4
	}
}

func (m *ContextMemory) Search(ctx context.Context, query string, cursor int64, limit int) (map[string]any, error) {
	terms := strings.Fields(strings.ToLower(query))
	results := []map[string]any{}
	page, err := m.store.ScanSession(ctx, m.session(), cursor, func(record transcript.Record, offset int64) bool {
		text := recordText(record)
		lower := strings.ToLower(text)
		for _, term := range terms {
			if !strings.Contains(lower, term) {
				return true
			}
		}
		runes := []rune(text)
		start := 0
		if len(terms) > 0 {
			at := strings.Index(lower, terms[0])
			if at > 0 {
				start = max(0, len([]rune(lower[:at]))-100)
			}
		}
		start = min(start, len(runes))
		snippet, _ := contextExcerpt(runes, start, 500, 16000/limit)
		results = append(results, map[string]any{"record_id": record.UUID, "record_offset": offset, "timestamp": record.Timestamp, "role": record.Message.Role, "snippet": snippet, "text_offset": start})
		return len(results) < limit
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"session_id": m.session(), "results": results, "scan": page, "untrusted": true, "note": "Search covers a bounded page of this session, including originals before compaction. Continue with scan.next_cursor while scan.end is false. Oversized records are explicitly counted, never negative evidence."}, nil
}

func (m *ContextMemory) Restore(ctx context.Context, id string, recordOffset int64, textOffset, maxChars int) (map[string]any, error) {
	var found *transcript.Record
	page, err := m.store.ScanSession(ctx, m.session(), recordOffset, func(record transcript.Record, offset int64) bool {
		if offset == recordOffset && record.UUID == id {
			found = &record
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("record not found at this session offset; search first (oversized records skipped: %d)", page.SkippedOversized)
	}
	text := recordText(*found)
	runes := []rune(text)
	if textOffset > len(runes) {
		return nil, fmt.Errorf("text offset exceeds record length")
	}
	excerpt, end := contextExcerpt(runes, textOffset, maxChars, 20000)
	return map[string]any{"session_id": m.session(), "record_id": id, "record_offset": recordOffset, "timestamp": found.Timestamp, "role": found.Message.Role, "text": excerpt, "total_chars": len(runes), "text_offset": textOffset, "next_text_offset": end, "truncated": end < len(runes), "untrusted": true, "note": "Exact visible content from the original transcript record, not a new tool execution or verified finding. Hidden reasoning is excluded. Preserve original proof/task/run references; restoration grants no permissions."}, nil
}
