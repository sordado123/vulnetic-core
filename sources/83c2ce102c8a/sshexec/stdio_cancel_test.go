package sshexec

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBetaRemoteStdioKillOnCancellationAndRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "revoke"}[revoke], func(t *testing.T) {
			key, err := GenerateKeypair("fixture")
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.ParsePrivateKey(key.PrivateKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			signals := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				cfg := &ssh.ServerConfig{NoClientAuth: true}
				cfg.AddHostKey(signer)
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
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
						switch request.Type {
						case "exec":
							_ = request.Reply(true, nil)
						case "signal":
							var payload struct{ Signal string }
							if ssh.Unmarshal(request.Payload, &payload) == nil {
								signals <- payload.Signal
							}
							_ = channel.Close()
						}
					}
				}
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			ex := NewTaskExecutor(func() (*ssh.Client, error) {
				return DialPinned("127.0.0.1", port, "fixture", key.PrivateKeyPEM, key.PublicKeyOpenSSH)
			}, nil, ".vulnetic/fixture")
			defer ex.Close()
			if ex.ActiveSessions() != 0 {
				t.Fatal("lazy executor reported a session before dialing")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, _, closer, err := ex.OpenStdio(ctx, "python3 -u fixture.py", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			if ex.ActiveSessions() != 1 {
				t.Fatal("active SSH session was not counted")
			}
			if revoke {
				_ = ex.Close()
			} else {
				cancel()
			}
			select {
			case signal := <-signals:
				if signal != string(ssh.SIGKILL) {
					t.Fatalf("remote process received %q", signal)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SSH session closed without terminating its remote process")
			}
			_ = closer.Close()
			if ex.ActiveSessions() != 0 {
				t.Fatal("closed SSH session is still counted")
			}
		})
	}
}
