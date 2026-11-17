package sshexec

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialTimeout bounds both the TCP connect and the SSH handshake — a
// misconfigured firewall or a dead host must fail fast, not hang the
// request (or, for the health-check endpoint, the HTTP handler) forever.
const dialTimeout = 15 * time.Second

// Dial is the legacy, unpinned connector retained for local integration fixtures.
// Customer execution must use DialPinned.
func Dial(host string, port int, username string, privateKeyPEM []byte) (*ssh.Client, error) {
	return dial(host, port, username, privateKeyPEM, ssh.InsecureIgnoreHostKey())
}

// PinnedHostKey refuses first-use and changed keys; confirmation belongs to the user.
func PinnedHostKey(expected string) (ssh.HostKeyCallback, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expected))
	if err != nil {
		return nil, fmt.Errorf("SSH host key must be confirmed before connecting")
	}
	return func(_ string, _ net.Addr, actual ssh.PublicKey) error {
		if !bytes.Equal(key.Marshal(), actual.Marshal()) {
			return fmt.Errorf("SSH host key changed; connection blocked (%s)", ssh.FingerprintSHA256(actual))
		}
		return nil
	}, nil
}

func DialPinned(host string, port int, username string, privateKeyPEM []byte, hostKey string) (*ssh.Client, error) {
	callback, err := PinnedHostKey(hostKey)
	if err != nil {
		return nil, err
	}
	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(hostKey))
	algorithms := []string{key.Type()}
	if key.Type() == ssh.KeyAlgoRSA {
		algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return dial(host, port, username, privateKeyPEM, callback, algorithms...)
}

// DialPinnedConn authenticates an independently owned reverse-agent stream.
func DialPinnedConn(connection net.Conn, username string, privateKeyPEM []byte, hostKey string) (*ssh.Client, error) {
	callback, err := PinnedHostKey(hostKey)
	if err != nil {
		connection.Close()
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("sshexec: parse private key: %w", err)
	}
	key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(hostKey))
	algorithms := []string{key.Type()}
	if key.Type() == ssh.KeyAlgoRSA {
		algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	config := &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: callback, HostKeyAlgorithms: algorithms}
	return clientOnConnection(connection, "temporary-agent", config)
}

// ProbeHostKey performs only key exchange, without sending account credentials.
func ProbeHostKey(host string, port int) (string, string, error) {
	var observed ssh.PublicKey
	stop := fmt.Errorf("host key probe complete")
	cfg := &ssh.ClientConfig{User: "vulnetic-host-key-probe", Timeout: dialTimeout, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error { observed = key; return stop }}
	cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), dialTimeout)
	if err != nil {
		return "", "", err
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		return "", "", err
	}
	_, _, _, err = ssh.NewClientConn(connection, net.JoinHostPort(host, fmt.Sprint(port)), cfg)
	if observed == nil {
		return "", "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(observed))), ssh.FingerprintSHA256(observed), nil
}

func dial(host string, port int, username string, privateKeyPEM []byte, callback ssh.HostKeyCallback, algorithms ...string) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("sshexec: parse private key: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:              username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   callback,
		Timeout:           dialTimeout,
		HostKeyAlgorithms: algorithms,
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	connection, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("sshexec: connect: %w", err)
	}
	return clientOnConnection(connection, addr, cfg)
}

func clientOnConnection(connection net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	if err := connection.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		connection.Close()
		return nil, err
	}
	transport, channels, requests, err := ssh.NewClientConn(connection, addr, cfg)
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("sshexec: dial %s: %w", addr, err)
	}
	if err = connection.SetDeadline(time.Time{}); err != nil {
		transport.Close()
		return nil, err
	}
	return ssh.NewClient(transport, channels, requests), nil
}

// RunOnce opens a connection, runs one command to completion, and closes it
// — used by the connection validator (one-off health check) and anywhere
// else that doesn't need a reusable session. combined stdout+stderr.
func RunOnce(host string, port int, username string, privateKeyPEM []byte, command string) (output string, err error) {
	client, err := Dial(host, port, username, privateKeyPEM)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("sshexec: new session: %w", err)
	}
	defer session.Close()
	out, err := session.CombinedOutput(command)
	if err != nil {
		return string(out), fmt.Errorf("sshexec: run %q: %w", command, err)
	}
	return string(out), nil
}
