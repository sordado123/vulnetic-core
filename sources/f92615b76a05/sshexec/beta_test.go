package sshexec

import (
	"context"
	"golang.org/x/crypto/ssh"
	"io"
	"strings"
	"testing"
)

func TestPinnedHostKeyRejectsMissingAndChangedKeys(t *testing.T) {
	a, err := GenerateKeypair("host-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeypair("host-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PinnedHostKey(""); err == nil {
		t.Fatal("missing key accepted")
	}
	callback, err := PinnedHostKey(a.PublicKeyOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	ka, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(a.PublicKeyOpenSSH))
	kb, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(b.PublicKeyOpenSSH))
	if err := callback("host:22", nil, ka); err != nil {
		t.Fatal(err)
	}
	if err := callback("host:22", nil, kb); err == nil {
		t.Fatal("changed key accepted")
	}
}

func TestRevokedLazyExecutorNeverDials(t *testing.T) {
	called := false
	ex := NewLazyExecutor(func() (*ssh.Client, error) { called = true; return nil, nil }, nil)
	ex.Close()
	if _, err := ex.Start(context.Background(), "", nil, "echo no", io.Discard); err == nil {
		t.Fatal("revoked executor ran")
	}
	if called {
		t.Fatal("revocation still dialed")
	}
}

func TestRemoteDirectoryGuardsCommandAndEnvironment(t *testing.T) {
	command := commandInDir(".vulnetic/tasks/1", []string{"TEST=value"}, "echo proof")
	if !strings.Contains(command, " && (export TEST='value'; echo proof)") {
		t.Fatalf("directory failure could fall through: %s", command)
	}
}
