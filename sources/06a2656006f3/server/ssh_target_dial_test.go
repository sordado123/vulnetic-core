package server

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/sshexec"
	"github.com/sordado123/vulnetic/vault"
)

// TestDialTaskSSHTargetConnectsToRealTarget is a live integration test: it
// requires the throwaway OpenSSH container used throughout Fase B's manual
// verification (127.0.0.1:2222, user "testuser", linuxserver/openssh-server)
// to be running, and is skipped if it is not reachable — it is not part of
// the normal `go test ./...` contract, only a manual-verification aid.
func TestDialTaskSSHTargetConnectsToRealTarget(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer pg.Close()

	account, _, err := pg.CreateAccountWithAdmin(fmt.Sprintf("DialTest %d", time.Now().UnixNano()), fmt.Sprintf("dialtest-%d@test.local", time.Now().UnixNano()), "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pg.Exec(`DELETE FROM ssh_targets WHERE account_id = $1`, account.ID)
		pg.Exec(`DELETE FROM account_vault_keys WHERE account_id = $1`, account.ID)
		pg.Exec(`DELETE FROM users WHERE account_id = $1`, account.ID)
		pg.Exec(`DELETE FROM accounts WHERE id = $1`, account.ID)
	})

	kp, err := sshexec.GenerateKeypair("dial-test")
	if err != nil {
		t.Fatal(err)
	}

	// Install the generated public key into the running test container —
	// skip (not fail) if the container isn't there, since this test is a
	// manual-verification aid, not part of the standard suite.
	installCmd := exec.Command("docker", "exec", "-u", "testuser", "-e", "HOME=/config", "vulnetic-ssh-test",
		"sh", "-c", fmt.Sprintf("echo %s >> ~/.ssh/authorized_keys", shellSingleQuoteForTest(kp.PublicKeyOpenSSH)))
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Skipf("test SSH container (vulnetic-ssh-test) not reachable via docker exec: %v (%s)", err, out)
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	dek, err := pg.GetOrCreateAccountDEK(account.ID, kek)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.Seal(dek, kp.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	target, err := pg.CreateSSHTarget(account.ID, "dial-test-vps", "127.0.0.1", 2222, "testuser",
		sealed.Ciphertext, sealed.Nonce, kp.PublicKeyOpenSSH, kp.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{m: &Manager{pg: pg}, vaultKey: kek}
	dial := s.dialTaskSSHTarget(account.ID, target.ID)
	client, err := dial()
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	out, err := session.CombinedOutput("echo wired-via-dialTaskSSHTarget")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "wired-via-dialTaskSSHTarget" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func shellSingleQuoteForTest(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
