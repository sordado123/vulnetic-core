package vault

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----")
	sealed, err := Seal(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed.Ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	got, err := Open(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestOpenFailsWithWrongKey(t *testing.T) {
	key, _ := NewDEK()
	other, _ := NewDEK()
	sealed, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, sealed); err != ErrInvalidSealed {
		t.Fatalf("expected ErrInvalidSealed, got %v", err)
	}
}

func TestOpenFailsOnTamperedCiphertext(t *testing.T) {
	key, _ := NewDEK()
	sealed, err := Seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed.Ciphertext[0] ^= 0xFF
	if _, err := Open(key, sealed); err != ErrInvalidSealed {
		t.Fatalf("expected ErrInvalidSealed, got %v", err)
	}
}

func TestWrapDEKUnderMasterKey(t *testing.T) {
	kek, _ := NewDEK()
	dek, _ := NewDEK()
	wrapped, err := Seal(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := Open(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestLoadOrCreateMasterKeyPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	key1, err := LoadOrCreateMasterKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key1) != keySize {
		t.Fatalf("expected %d-byte key, got %d", keySize, len(key1))
	}
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); err != nil {
		t.Fatalf("expected key file to be written: %v", err)
	}
	key2, err := LoadOrCreateMasterKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("second load must return the same persisted key, not a new one")
	}
}

func TestLoadOrCreateMasterKeyEnvOverride(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, keySize)
	t.Setenv(masterKeyEnv, base64.StdEncoding.EncodeToString(key))
	got, err := LoadOrCreateMasterKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("env override must take precedence over the file")
	}
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); err == nil {
		t.Fatal("env override must not also write a key file")
	}
}
