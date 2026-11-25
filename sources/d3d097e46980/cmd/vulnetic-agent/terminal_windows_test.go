package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/internal/winsecure"
)

func TestWindowsTerminalRejectsUnsafeInputsBeforeConnecting(t *testing.T) {
	if err := requireWindowsTerminalUser(); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	sid, err := winsecure.UserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err = winsecure.Restrict(base, sid, true); err != nil {
		t.Fatal(err)
	}
	enrollment := filepath.Join(base, "enrollment")
	if err = os.WriteFile(enrollment, []byte("invalid-token"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		server, directory string
		lifetime          int
		expected          string
	}{
		{"http://public.fixture.invalid", base, 300, "HTTPS"},
		{"http://127.0.0.1:1", base, 299, "lifetime"},
		{"http://127.0.0.1:1", base, 604801, "lifetime"},
		{"http://127.0.0.1:1", "", 300, "workspace"},
		{"http://127.0.0.1:1", enrollment, 300, "workspace"},
		{"http://127.0.0.1:1", base, 300, "token"},
	} {
		err = runWindowsTerminal(context.Background(), test.server, enrollment, test.directory, test.lifetime, io.Discard)
		if err == nil || !strings.Contains(err.Error(), test.expected) {
			t.Fatalf("unsafe input reached connection: %v (expected %s)", err, test.expected)
		}
		if _, e := os.Stat(enrollment); e != nil {
			t.Fatal("invalid input removed an unconsumed enrollment file", e)
		}
	}
}
