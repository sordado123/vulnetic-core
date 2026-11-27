package notify

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestBetaNotificationRequiresRemoteDial(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	if _, err := doJSON(context.Background(), "POST", "http://127.0.0.1:1/private", nil, nil); err == nil {
		t.Fatal("HTTP delivery accepted without a VPS")
	}
	if _, err := emailDial(context.Background(), "127.0.0.1:1", "localhost", false); err == nil {
		t.Fatal("SMTP delivery accepted without a VPS")
	}
	calls := 0
	ctx := WithRemoteDial(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("VPS unavailable")
	})
	if _, err := doJSON(ctx, "POST", "http://remote.invalid/hook", nil, nil); err == nil || calls != 1 {
		t.Fatalf("HTTP must use the failing remote dial exactly once: %d %v", calls, err)
	}
	if _, err := emailDial(ctx, "remote.invalid:25", "remote.invalid", false); err == nil || calls != 2 {
		t.Fatalf("SMTP must use the failing remote dial exactly once: %d %v", calls, err)
	}
}

func TestBetaNotificationHTTPUsesRemoteConnection(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	result := make(chan error, 1)
	ctx := WithRemoteDial(context.Background(), func(_ context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != "remote.invalid:80" {
			t.Errorf("unexpected remote destination: %s %s", network, addr)
		}
		client, remote := net.Pipe()
		go func() {
			defer remote.Close()
			req, err := http.ReadRequest(bufio.NewReader(remote))
			if err == nil {
				var body []byte
				body, err = io.ReadAll(req.Body)
				req.Body.Close()
				if string(body) != `{"proof":"remote"}` || req.URL.Path != "/hook" {
					err = errors.New("wrong remote request")
				}
			}
			if err == nil {
				_, err = io.Copy(remote, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}
			result <- err
		}()
		return client, nil
	})
	body, err := doJSON(ctx, "POST", "http://remote.invalid/hook", nil, map[string]string{"proof": "remote"})
	if err != nil || string(body) != "ok" {
		t.Fatalf("remote HTTP response: %q %v", body, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
