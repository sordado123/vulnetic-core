//go:build linux

package reverseagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestEncryptedReconnectState(t *testing.T) {
	credential := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credential, "vulnetic-state-key"), key, 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credential)
	testReconnectState(t)
}
func testReconnectState(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(private)
	file := filepath.Join(t.TempDir(), "state.enc")
	state := clientState{ServerURL: "https://fixture.example.test", Username: "fixture", Directory: "/home/fixture", PrivateKey: private, Enrollment: Enrollment{RuntimeToken: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ClientPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), LeaseSeconds: 10800, ExpiresAt: time.Now().Add(3 * time.Hour).UTC()}}
	if err = saveClientState(t.Context(), file, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), state.Enrollment.RuntimeToken) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(private)) {
		t.Fatal("plaintext reconnect credentials reached disk")
	}
	cfg := ClientConfig{ServerURL: state.ServerURL, Username: state.Username, Directory: state.Directory, StateFile: file}
	restored, ok, err := loadClientState(t.Context(), cfg)
	if err != nil || !ok || !restored.Enrollment.ExpiresAt.Equal(state.Enrollment.ExpiresAt) || string(restored.PrivateKey) != string(private) {
		t.Fatal("encrypted identity did not survive process state reload", err)
	}
	cfg.ServerURL = "https://another.example.test"
	if _, _, err = loadClientState(t.Context(), cfg); !errors.Is(err, ErrLeaseEnded) {
		t.Fatal("cross-platform credential reuse accepted")
	}
	cfg.ServerURL = state.ServerURL
	state.Enrollment.ExpiresAt = time.Now().Add(-time.Minute)
	if err = saveClientState(t.Context(), file, state); err != nil {
		t.Fatal(err)
	}
	if err = Run(context.Background(), cfg); !errors.Is(err, ErrLeaseEnded) {
		t.Fatal("stored lease was renewed after expiry", err)
	}
	raw[0] ^= 1
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadClientState(t.Context(), cfg); !errors.Is(err, ErrLeaseEnded) {
		t.Fatal("damaged encrypted state accepted")
	}
}

func TestAgentDedicatedUserPermissions(t *testing.T) {
	if os.Getenv("VULNETIC_TEST_NONROOT") == "1" {
		if os.Geteuid() == 0 {
			t.Fatal("agent child retained root")
		}
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(status, []byte("NoNewPrivs:\t1")) || !bytes.Contains(status, []byte("CapEff:\t0000000000000000")) {
			t.Fatal("privilege elevation or capabilities still enabled")
		}
		if _, err = os.ReadFile("/etc/shadow"); err == nil {
			t.Fatal("agent child could read root credentials")
		}
		output, err := exec.Command("id", "-u").Output()
		if err != nil || strings.TrimSpace(string(output)) != "10001" {
			t.Fatal("commands did not retain the dedicated UID", err)
		}
		testReconnectState(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("UID transition requires the isolated root Linux lab")
	}
	directory, err := os.MkdirTemp("", "vulnetic-nonroot-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(directory, "test-agent")
	if err = os.WriteFile(child, binary, 0555); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credentials")
	if err = os.Mkdir(credential, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(credential, "vulnetic-state-key")
	if err = os.WriteFile(name, key, 0400); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{credential, name} {
		if err = os.Chown(name, 10001, 10001); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(t.Context(), "setpriv", "--reuid=10001", "--regid=10001", "--clear-groups", "--no-new-privs", child, "-test.run=^TestAgentDedicatedUserPermissions$", "-test.v")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "CREDENTIALS_DIRECTORY=" + credential, "VULNETIC_TEST_NONROOT=1"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("non-root executor/state test: %v %s", err, output)
	}
}
