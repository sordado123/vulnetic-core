package db

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/vault"
)

func cleanupSSHTestAccount(d *DB, accountID int64) {
	d.Exec(`DELETE FROM ssh_targets WHERE account_id = $1`, accountID)
	d.Exec(`DELETE FROM account_vault_keys WHERE account_id = $1`, accountID)
	d.Exec(`DELETE FROM users WHERE account_id = $1`, accountID)
	d.Exec(`DELETE FROM accounts WHERE id = $1`, accountID)
}

func newTestAccount(t *testing.T, d *DB, label string) int64 {
	n := time.Now().UnixNano()
	account, _, err := d.CreateAccountWithAdmin(fmt.Sprintf("SSH Test %s %d", label, n), fmt.Sprintf("ssh-test-%s-%d@test.local", label, n), "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupSSHTestAccount(d, account.ID) })
	return account.ID
}

func TestSSHTargetCRUDScopedByAccount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	accountA := newTestAccount(t, d, "a")
	accountB := newTestAccount(t, d, "b")

	target, err := d.CreateSSHTarget(accountA, "prod-vps", "203.0.113.10", 22, "root",
		[]byte("ciphertext"), []byte("nonce1234567"), "ssh-ed25519 AAAA fake", "SHA256:fake")
	if err != nil {
		t.Fatal(err)
	}
	if target.Status != SSHTargetPending {
		t.Fatalf("new target should start pending, got %q", target.Status)
	}

	// Owner sees it.
	list, err := d.ListSSHTargets(accountA)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != target.ID {
		t.Fatalf("expected exactly the one target owned by accountA, got %+v", list)
	}
	got, err := d.GetSSHTarget(accountA, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "203.0.113.10" {
		t.Fatalf("unexpected host: %q", got.Host)
	}

	// A different account cannot see, fetch, update-health, or delete it.
	listB, err := d.ListSSHTargets(accountB)
	if err != nil {
		t.Fatal(err)
	}
	if len(listB) != 0 {
		t.Fatalf("accountB should see zero targets, got %d", len(listB))
	}
	if _, err := d.GetSSHTarget(accountB, target.ID); !errors.Is(err, ErrSSHTargetNotFound) {
		t.Fatalf("cross-account get should be ErrSSHTargetNotFound, got %v", err)
	}
	if err := d.UpdateSSHTargetHealth(accountB, target.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if reread, _ := d.GetSSHTarget(accountA, target.ID); reread.Status != SSHTargetPending {
		t.Fatalf("cross-account health update must not have affected the real owner's row, status=%q", reread.Status)
	}
	if err := d.DeleteSSHTarget(accountB, target.ID); !errors.Is(err, ErrSSHTargetNotFound) {
		t.Fatalf("cross-account delete should be ErrSSHTargetNotFound, got %v", err)
	}

	// Owner's own health update and delete work.
	if err := d.UpdateSSHTargetHealth(accountA, target.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if reread, err := d.GetSSHTarget(accountA, target.ID); err != nil || reread.Status != SSHTargetVerified {
		t.Fatalf("owner health update should mark verified, got %+v err=%v", reread, err)
	}
	if err := d.UpdateSSHTargetHealth(accountA, target.ID, false, "connection refused"); err != nil {
		t.Fatal(err)
	}
	if reread, err := d.GetSSHTarget(accountA, target.ID); err != nil || reread.Status != SSHTargetFailed || reread.LastError != "connection refused" {
		t.Fatalf("owner health update should mark failed with message, got %+v err=%v", reread, err)
	}
	if err := d.DeleteSSHTarget(accountA, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetSSHTarget(accountA, target.ID); !errors.Is(err, ErrSSHTargetNotFound) {
		t.Fatal("target should be gone after delete")
	}
}

func TestGetOrCreateAccountDEKIsStableAndPerAccount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	accountA := newTestAccount(t, d, "dek-a")
	accountB := newTestAccount(t, d, "dek-b")
	kek, err := vault.NewDEK() // same shape as a master key: 32 random bytes
	if err != nil {
		t.Fatal(err)
	}

	dekA1, err := d.GetOrCreateAccountDEK(accountA, kek)
	if err != nil {
		t.Fatal(err)
	}
	dekA2, err := d.GetOrCreateAccountDEK(accountA, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dekA1, dekA2) {
		t.Fatal("second call must return the same DEK, not generate a new one")
	}

	dekB, err := d.GetOrCreateAccountDEK(accountB, kek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dekA1, dekB) {
		t.Fatal("two different accounts must never share a DEK")
	}

	// A secret encrypted under accountA's DEK must not decrypt under accountB's.
	sealed, err := vault.Seal(dekA1, []byte("private key material"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Open(dekB, sealed); err == nil {
		t.Fatal("decrypting accountA's secret under accountB's DEK must fail")
	}
	plain, err := vault.Open(dekA1, sealed)
	if err != nil || string(plain) != "private key material" {
		t.Fatalf("round trip under the owning account's DEK failed: %q, err=%v", plain, err)
	}
}
