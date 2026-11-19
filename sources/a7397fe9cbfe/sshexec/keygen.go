// Package sshexec implements Fase B's Modo A: running task commands on a
// customer's own VPS over SSH instead of locally.
package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GeneratedKeypair is a freshly generated ed25519 SSH keypair, ready to
// encrypt (PrivateKeyPEM) and display (PublicKeyOpenSSH/Fingerprint).
type GeneratedKeypair struct {
	// PrivateKeyPEM is the OpenSSH PEM encoding of the private key — the
	// caller encrypts this (vault.Seal) before persisting it; it is never
	// written to disk or the database in the clear.
	PrivateKeyPEM []byte
	// PublicKeyOpenSSH is the "ssh-ed25519 AAAA... comment" line the
	// customer appends to their VPS's ~/.ssh/authorized_keys. Not a secret.
	PublicKeyOpenSSH string
	Fingerprint      string
}

// GenerateKeypair creates a new ed25519 SSH keypair. Vulnetic always
// generates the key itself rather than accepting an uploaded one — an
// account bringing an existing key would mean Vulnetic now holds a secret
// that may be reused for other access that has nothing to do with this
// platform. comment becomes the trailing label on the public key line
// (e.g. "vulnetic-<account>-<target-name>"), purely informational.
func GenerateKeypair(comment string) (GeneratedKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedKeypair{}, fmt.Errorf("sshexec: generate ed25519 key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return GeneratedKeypair{}, fmt.Errorf("sshexec: marshal private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return GeneratedKeypair{}, fmt.Errorf("sshexec: signer from key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return GeneratedKeypair{}, fmt.Errorf("sshexec: public key: %w", err)
	}
	authorized := ssh.MarshalAuthorizedKey(sshPub)
	return GeneratedKeypair{
		PrivateKeyPEM:    pem.EncodeToMemory(block),
		PublicKeyOpenSSH: fmt.Sprintf("%s %s", trimNewline(authorized), comment),
		Fingerprint:      ssh.FingerprintSHA256(signer.PublicKey()),
	}, nil
}

func trimNewline(b []byte) string {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		return string(b[:n-1])
	}
	return string(b)
}
