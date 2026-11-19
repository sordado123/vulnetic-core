package db

import (
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
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
		t.Fatal(pending, err)
	}
	if pending, err := d.UsagePending(2); err != nil || pending != 0 {
		t.Fatal("foreign pending usage visible", pending, err)
	}
}
