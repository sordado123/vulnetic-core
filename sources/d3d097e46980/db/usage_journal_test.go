package db

import (
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestUsageJournalRetainsRejectedInsertByAccount(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	d := &DB{Querier: scopeFailure{errors.New("synthetic database unavailable")}, hasAccount: true, accountID: 1, usageJournal: &usageJournal{root: root}}
	u := &LLMUsage{AccountID: 1, CallID: uuid.NewString(), RecordedAt: time.Now().UTC(), Model: "fixture", InputTokens: 123}
	if err = d.journalUsage(u); err == nil {
		t.Fatal("insert failure hidden")
	}
	if _, err = os.Stat(filepath.Join(directory, "1", u.CallID+".json")); err != nil {
		t.Fatal("durable retry missing", err)
	}
	if pending, err := d.UsagePending(1); err != nil || pending != 1 {
		// Windows refuses directory FlushFileBuffers. Verify the fail-closed state,
		// rather than claiming a durable directory sync or weakening the journal.
		dir, openErr := root.Open("1")
		if openErr != nil {
			t.Fatal(openErr)
		}
		syncErr := dir.Sync()
		dir.Close()
		if runtime.GOOS != "windows" || syncErr == nil || pending != 1 || err == nil || err.Error() != "usage journal requires recovery" {
			t.Fatal(pending, err, syncErr)
		}
	}
	if pending, err := d.UsagePending(2); err != nil || pending != 0 {
		t.Fatal("foreign pending usage visible", pending, err)
	}
}
