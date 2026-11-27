package sshexec

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateKeypairProducesValidParsableKeys(t *testing.T) {
	kp, err := GenerateKeypair("vulnetic-1-test-target")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kp.PrivateKeyPEM), "OPENSSH PRIVATE KEY") {
		t.Fatalf("private key does not look like an OpenSSH PEM block: %q", kp.PrivateKeyPEM)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("generated private key does not parse: %v", err)
	}
	if !strings.HasPrefix(kp.PublicKeyOpenSSH, "ssh-ed25519 ") {
		t.Fatalf("public key line has unexpected prefix: %q", kp.PublicKeyOpenSSH)
	}
	if !strings.HasSuffix(kp.PublicKeyOpenSSH, "vulnetic-1-test-target") {
		t.Fatalf("public key line missing comment: %q", kp.PublicKeyOpenSSH)
	}
	wantFP := ssh.FingerprintSHA256(signer.PublicKey())
	if kp.Fingerprint != wantFP {
		t.Fatalf("fingerprint mismatch: got %q want %q", kp.Fingerprint, wantFP)
	}
}

func TestGenerateKeypairIsRandomEachCall(t *testing.T) {
	a, err := GenerateKeypair("x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeypair("x")
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("two generated keypairs must not share a fingerprint")
	}
}
