package evidence

import (
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"os"
	"testing"
	"time"
)

func TestRuntimePreservesStoredEvidence(t *testing.T) {
	if os.Getenv("VULNETIC_PG_APP_PASSWORD") == "" {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", "beta-integration-test-password-only")
	}
	store, input, _ := evidenceFixture(t)
	seedExchange(t, store, "runtime-evidence", []byte("preserved response"), false)
	finding, err := store.Record(t.Context(), input, []db.TrafficRef{{TrafficID: "runtime-evidence", Role: "proof", Note: "original"}})
	if err != nil {
		t.Fatal(err)
	}
	dsn, err := config.PostgresAppDSN()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := db.OpenRuntime(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	store.DB = runtime.ForAccount(db.LegacyAccountID)
	bid := finding.Traffic.Bindings[0].ID
	binding, err := store.Binding(t.Context(), finding.FindingID, bid)
	if err != nil {
		t.Fatal("historical evidence became inaccessible", err)
	}
	if err = store.Collect(t.Context(), time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("runtime was allowed to collect global evidence")
	}
	if _, err = store.Binding(t.Context(), finding.FindingID, bid); err != nil {
		t.Fatal("cleanup changed evidence metadata", err)
	}
	if err = verifyFile(func() string { path, _ := hashPath(store.Dir, binding.Snapshot.RespHash); return path }(), binding.Snapshot.RespHash, binding.Snapshot.RespLen); err != nil {
		t.Fatal("evidence body lost", err)
	}
}
