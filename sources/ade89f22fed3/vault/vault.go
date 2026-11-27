// Package vault provides envelope encryption for per-account secrets (SSH
// private keys today; anything else that needs encryption at rest later).
//
// Two layers, both AES-256-GCM:
//   - A single server-wide master key (KEK), loaded once at startup via
//     LoadOrCreateMasterKey — same file-based pattern as server/auth.go's
//     JWT signing key (a 0600 file next to the executable, env var override).
//   - One data-encryption-key (DEK) per account, generated with NewDEK and
//     wrapped (encrypted) by the KEK before it is stored (see
//     db.AccountVaultKey). The DEK itself then encrypts the actual secret
//     (e.g. an SSH private key) via Seal/Open.
//
// This indirection means compromising one account's stored DEK never exposes
// another account's, and rotating the master key only requires re-wrapping
// DEKs (small), not re-encrypting every secret (potentially large).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	keySize        = 32 // AES-256
	masterKeyEnv   = "VULNETIC_VAULT_KEY"
	masterKeyFile  = "vault.key"
	legacyKeyPerms = 0o600
)

// ErrInvalidSealed is returned when a Sealed value's nonce/ciphertext cannot
// have been produced by Seal (wrong size, truncated, or tampered).
var ErrInvalidSealed = errors.New("vault: invalid sealed value")

// Sealed is ciphertext plus the nonce used to produce it. Safe to store
// verbatim (e.g. as two bytea columns, or concatenated) — it carries no
// secret on its own without the key.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// NewDEK generates a fresh random 32-byte data-encryption key.
func NewDEK() ([]byte, error) {
	buf := make([]byte, keySize)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("vault: generate DEK: %w", err)
	}
	return buf, nil
}

// Seal encrypts plaintext with key (must be 32 bytes) under a fresh random
// nonce. Used both to wrap a DEK under the master key and to encrypt an
// actual secret under its account's DEK — same primitive, different key.
func Seal(key, plaintext []byte) (Sealed, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("vault: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, fmt.Errorf("vault: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("vault: generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return Sealed{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Open decrypts a Sealed value with key. Fails closed: any corruption or
// wrong key returns ErrInvalidSealed rather than garbage plaintext.
func Open(key []byte, s Sealed) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: new gcm: %w", err)
	}
	if len(s.Nonce) != gcm.NonceSize() {
		return nil, ErrInvalidSealed
	}
	plaintext, err := gcm.Open(nil, s.Nonce, s.Ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidSealed
	}
	return plaintext, nil
}

// LoadOrCreateMasterKey resolves the server-wide KEK: VULNETIC_VAULT_KEY (a
// base64-encoded 32-byte key) takes precedence when set; otherwise a key is
// read from keyDir/vault.key, or generated and persisted there (0600) if
// absent. keyDir is config.BaseDir() in production — same directory as the
// JWT signing key, outside the browsable data/ workspace.
func LoadOrCreateMasterKey(keyDir string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(masterKeyEnv)); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("vault: %s is not valid base64: %w", masterKeyEnv, err)
		}
		if len(key) != keySize {
			return nil, fmt.Errorf("vault: %s must decode to %d bytes, got %d", masterKeyEnv, keySize, len(key))
		}
		return key, nil
	}
	path := filepath.Join(keyDir, masterKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decErr == nil && len(key) == keySize {
			return key, nil
		}
		return nil, fmt.Errorf("vault: %s is corrupt (expected %d-byte base64 key)", path, keySize)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vault: read master key: %w", err)
	}
	key, err := NewDEK() // same shape as a DEK: 32 random bytes
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, legacyKeyPerms)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateMasterKey(keyDir)
	}
	if err != nil {
		return nil, fmt.Errorf("vault: create master key: %w", err)
	}
	_, err = f.Write([]byte(encoded))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("vault: persist master key: %w", err)
	}
	return key, nil
}
