package sshexec

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBetaSSHExecutorUsesPinnedRemoteSession(t *testing.T) {
	host, err := GenerateKeypair("host")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(host.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		// OpenSSH commonly offers several host keys; negotiate the confirmed ED25519 key.
		cfg.AddHostKey(otherSigner)
		cfg.AddHostKey(signer)
		server, channels, requests, err := ssh.NewServerConn(connection, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			for request := range requests {
				if request.Type != "exec" {
					request.Reply(false, nil)
					continue
				}
				var command struct{ Command string }
				ssh.Unmarshal(request.Payload, &command)
				commands <- command.Command
				request.Reply(true, nil)
				channel.Write([]byte("remote-proof"))
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				channel.Close()
				break
			}
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ex := NewTaskExecutor(func() (*ssh.Client, error) {
		return DialPinned("127.0.0.1", port, "test", host.PrivateKeyPEM, host.PublicKeyOpenSSH)
	}, nil, ".vulnetic/accounts/2/tasks/7")
	defer ex.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	handle, err := ex.Start(ctx, "/server/private", []string{"TEST=remote"}, "echo proof", &output)
	if err != nil {
		t.Fatal(err)
	}
	if err = handle.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "remote-proof" {
		t.Fatalf("output: %q", output.String())
	}
	select {
	case command := <-commands:
		if strings.Contains(command, "/server/private") || !strings.Contains(command, ".vulnetic/accounts/2/tasks/7") {
			t.Fatalf("wrong execution directory: %s", command)
		}
	case <-ctx.Done():
		t.Fatal("remote command was not received")
	}
}
