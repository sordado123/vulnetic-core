package runstate

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

type Stage struct {
	Name        string    `json:"name"`
	OperationID string    `json:"operation_id,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	DurationMS  int64     `json:"duration_ms"`
	Status      string    `json:"status"`
}
type operationKey struct{}

func WithOperation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, operationKey{}, id)
}

// Nested stages overlap; do not sum these durations as total execution time.
// Metadata only, bounded in memory and persisted by the next normal state transition.
func RecordStage(ctx context.Context, name string, start time.Time, failed bool) {
	s := From(ctx)
	if s == nil {
		return
	}
	if name != "dns" && name != "connect" && name != "tls" && name != "tool" {
		return
	}
	id, _ := ctx.Value(operationKey{}).(string)
	if len(id) > 128 {
		id = ""
	}
	status := "ok"
	if failed {
		status = "failed"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.FinishedAt != nil {
		return
	}
	s.snapshot.Stages = append(s.snapshot.Stages, Stage{name, id, start.UTC(), time.Since(start).Milliseconds(), status})
	if len(s.snapshot.Stages) > 32 {
		s.snapshot.Stages = append([]Stage{}, s.snapshot.Stages[len(s.snapshot.Stages)-32:]...)
	}
}

func TraceHTTP(ctx context.Context) context.Context {
	var mu sync.Mutex
	var at time.Time
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() { mu.Lock(); at = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			mu.Lock()
			start := at
			mu.Unlock()
			if !start.IsZero() {
				RecordStage(ctx, "tls", start, err != nil)
			}
		},
	})
}
