// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package transcript

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/llm"
)

func TestAccountTranscriptPreservesLegacyAndConfinesWrites(t *testing.T) {
	base := t.TempDir()
	legacy := NewStore(filepath.Join(base, "legacy"))
	legacy.NewWriter("conv-7", "").RecordMessage(llm.UserText("preserved history"), llm.Usage{})
	account := filepath.Join(base, "account")
	store := NewAccountStore(filepath.Join(account, "transcripts"), account, filepath.Join(base, "legacy"))
	for range 2 {
		records, err := store.Load(store.MainPath("conv-7"))
		if err != nil || len(records) != 1 || records[0].Message.Text() != "preserved history" {
			t.Fatalf("legacy migration: %d %v", len(records), err)
		}
	}
	if _, err := os.Stat(legacy.MainPath("conv-7")); err != nil {
		t.Fatal("legacy history was removed", err)
	}
	if err := store.Append(filepath.Join(base, "escaped.jsonl"), Record{Type: "boundary"}); err == nil {
		t.Fatal("write escaped account")
	}
	if _, err := store.Load(filepath.Join(base, "escaped.jsonl")); err == nil {
		t.Fatal("read escaped account")
	}
}
