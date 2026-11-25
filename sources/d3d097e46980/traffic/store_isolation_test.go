package traffic

import "testing"

// Per-account ingest isolation (#traffic beta): each account gets its own
// OpenStore instance, so the store object IS the tenant boundary. Traffic
// recorded into one account's store must be invisible — unlistable and
// unreadable — from another's, with no shared package-level state leaking across.
func TestOpenStoreIsolatesAccounts(t *testing.T) {
	a, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store A: %v", err)
	}
	defer a.Close()
	b, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store B: %v", err)
	}
	defer b.Close()

	if err := a.RecordExternal(ExternalExchange{
		Method:          "POST",
		URL:             "https://app.a.test/login",
		Status:          200,
		RequestHeaders:  map[string]string{"content-type": "application/json"},
		RequestBody:     `{"user":"tenant-a","password":"secret-a"}`,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"token":"tok-a"}`,
	}); err != nil {
		t.Fatalf("record into A: %v", err)
	}

	// A sees its own exchange; B sees nothing.
	if n, _ := a.Count(); n != 1 {
		t.Fatalf("A count = %d, want 1", n)
	}
	if n, _ := b.Count(); n != 0 {
		t.Fatalf("B count = %d, want 0 (cross-tenant leak)", n)
	}
	rows, total, err := b.Page(PageQuery{Query: "tenant-a", RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(rows) != 0 {
		t.Fatalf("B search found A's traffic: %d rows (total %d)", len(rows), total)
	}

	// B cannot read A's exchange even with its exact id (ids are per-store).
	aRows, _, err := a.Page(PageQuery{RespMin: -1, RespMax: -1}, 0, 10)
	if err != nil || len(aRows) != 1 {
		t.Fatalf("A page: rows=%d err=%v", len(aRows), err)
	}
	if _, _, err := b.Get(aRows[0].ID); err == nil {
		t.Fatalf("B.Get resolved A's exchange id %q — cross-tenant read", aRows[0].ID)
	}
}
