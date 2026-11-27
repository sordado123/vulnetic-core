package reverseagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/internal/winsecure"
)

func TestWindowsDPAPIReconnectState(t *testing.T) {
	dir := t.TempDir()
	sid, err := winsecure.UserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err = winsecure.Restrict(dir, sid, true); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := clientState{ServerURL: "https://fixture.invalid", Username: "dedicated", Directory: dir, PrivateKey: private, Enrollment: Enrollment{RuntimeToken: "synthetic-private-token", ExpiresAt: time.Now().Add(time.Hour)}}
	file := filepath.Join(dir, "state.enc")
	if err = saveClientState(t.Context(), file, state); err != nil {
		t.Fatal(err)
	}
	cipher, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte(state.Enrollment.RuntimeToken)) || bytes.Contains(cipher, private) {
		t.Fatal("plaintext credentials persisted")
	}
	cfg := ClientConfig{ServerURL: state.ServerURL, Username: state.Username, Directory: dir, StateFile: file}
	loaded, ok, err := loadClientState(t.Context(), cfg)
	if err != nil || !ok || !loaded.Enrollment.ExpiresAt.Equal(state.Enrollment.ExpiresAt) || !bytes.Equal(loaded.PrivateKey, private) {
		t.Fatal("identity or original deadline changed:", err)
	}
	cfg.ServerURL = "https://another.invalid"
	if _, _, err = loadClientState(t.Context(), cfg); !errors.Is(err, ErrLeaseEnded) {
		t.Fatal("cross-platform state reuse accepted")
	}
	cfg.ServerURL = state.ServerURL
	cipher[len(cipher)-1] ^= 1
	if err = os.WriteFile(file, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadClientState(t.Context(), cfg); !errors.Is(err, ErrLeaseEnded) {
		t.Fatal("tampered state accepted")
	}
}

func TestWindowsNativeShellAndProcessTree(t *testing.T) {
	dir := t.TempDir()
	raw := EncodeNative(NativeCommand{Kind: "exec", Directory: "task", Env: []string{"VULNETIC_TEST_VALUE=quoted ' value"}, Command: "[Console]::Write($env:VULNETIC_TEST_VALUE)"})
	c, err := shellCommand(raw, dir)
	if err != nil {
		t.Fatal(err)
	}
	output, err := c.CombinedOutput()
	if err != nil || string(output) != "quoted ' value" {
		t.Fatalf("native command: %s %v", output, err)
	}
	if _, err = shellCommand(EncodeNative(NativeCommand{Kind: "exec", Directory: "../outside", Command: "exit 0"}), dir); err == nil {
		t.Fatal("workspace traversal accepted")
	}
	if _, err = shellCommand("echo unstructured", dir); err == nil {
		t.Fatal("unstructured shell accepted")
	}
	testWindowsJobTree(t, dir)
}
