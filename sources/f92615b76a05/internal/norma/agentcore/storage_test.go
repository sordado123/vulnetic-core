// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package agentcore

import (
	"context"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/harness"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/internal/norma/transcript"
)

func TestAccountStorageFailureStopsBeforeModelCall(t *testing.T) {
	root := t.TempDir()
	store := transcript.NewAccountStore(filepath.Join(root, "transcripts"), root, "")
	if err := os.MkdirAll(store.MainPath("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	session := NewSession(Options{Transcript: store, SessionID: "fixture", DisableBackgroundTasks: true, Deps: harness.QueryDeps{
		CallModel: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
			calls++
			return func(func(llm.StreamEvent, error) bool) {}
		},
	}})
	defer session.Close()
	var failure error
	for _, err := range session.Prompt(t.Context(), "Must persist before inference") {
		if err != nil {
			failure = err
		}
	}
	if failure == nil || calls != 0 {
		t.Fatalf("storage error=%v model calls=%d", failure, calls)
	}
}
