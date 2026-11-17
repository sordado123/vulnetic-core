package llmpool

import (
	"sync"
	"testing"
	"time"
)

func TestHealthCallbacksPreserveMutationOrder(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	persisted := false
	reg := NewRegistry(func(id int64, s State) { close(entered); <-release; mu.Lock(); persisted = true; mu.Unlock() }, func(id int64) { mu.Lock(); persisted = false; mu.Unlock() })
	tripDone := make(chan struct{})
	go func() { reg.Trip(1, "fixture", true); close(tripDone) }()
	<-entered
	passDone := make(chan struct{})
	go func() { reg.Pass(1); close(passDone) }()
	select {
	case <-passDone:
		t.Fatal("later callback overtook blocked persistence")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-tripDone
	<-passDone
	mu.Lock()
	defer mu.Unlock()
	if persisted {
		t.Fatal("stale failure survived later recovery")
	}
}
