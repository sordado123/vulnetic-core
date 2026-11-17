package reverseagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type EnrollmentRequest struct {
	HostKey  string `json:"host_key"`
	Username string `json:"username"`
	Platform string `json:"platform,omitempty"`
}
type Enrollment struct {
	RuntimeToken    string    `json:"runtime_token"`
	ClientPublicKey string    `json:"client_public_key"`
	LeaseSeconds    int       `json:"lease_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type ClientConfig struct {
	ServerURL       string
	EnrollmentToken string
	Username        string
	Directory       string
	HTTPClient      *http.Client
	StateFile       string // ciphertext only, sealed by systemd-creds to this VPS
	EnrollmentFile  string
	OnLease         func(time.Time) // Foreground status only; receives no connection credential.
}

var ErrLeaseEnded = errors.New("agent access expired or was revoked; generate a new installation command")

type clientState struct {
	ServerURL  string     `json:"server_url"`
	Username   string     `json:"username"`
	Directory  string     `json:"directory"`
	PrivateKey []byte     `json:"private_key"`
	Enrollment Enrollment `json:"enrollment"`
}

// Plain HTTP is accepted only on literal loopback/localhost for isolated labs.
func ValidateServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("a root HTTPS platform URL is required")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback()))) {
		return nil, errors.New("the platform URL must use HTTPS")
	}
	u.Path = ""
	return u, nil
}

func Run(ctx context.Context, cfg ClientConfig) error {
	base, err := ValidateServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	client := http.Client{Timeout: 20 * time.Second}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	if client.Timeout == 0 {
		client.Timeout = 20 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	state, loaded, err := loadClientState(ctx, cfg)
	if err != nil {
		return err
	}
	if !loaded {
		state, err = enroll(ctx, cfg, base, &client)
		if err != nil {
			return err
		}
		if cfg.StateFile != "" {
			if err = saveClientState(ctx, cfg.StateFile, state); err != nil {
				return fmt.Errorf("%w: encrypted reconnect state could not be saved", ErrLeaseEnded)
			}
			if cfg.EnrollmentFile != "" {
				if err = os.Truncate(cfg.EnrollmentFile, 0); err != nil {
					return err
				}
			}
		}
	}
	enrollment := state.Enrollment
	signer, err := ssh.NewSignerFromKey(ed25519.PrivateKey(state.PrivateKey))
	if err != nil {
		return err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(enrollment.ClientPublicKey))
	if err != nil {
		return errors.New("invalid platform identity")
	}
	token, err := base64.RawURLEncoding.DecodeString(enrollment.RuntimeToken)
	if err != nil || len(token) != 32 {
		return errors.New("invalid connection credential")
	}
	if !time.Now().Before(enrollment.ExpiresAt) {
		return ErrLeaseEnded
	}
	lease, cancel := context.WithDeadline(ctx, enrollment.ExpiresAt)
	defer cancel()
	if cfg.OnLease != nil {
		deadline, _ := lease.Deadline()
		cfg.OnLease(deadline)
	}
	cfg.EnrollmentToken = ""
	base.Path = "/agent/connect"
	if base.Scheme == "https" {
		base.Scheme = "wss"
	} else {
		base.Scheme = "ws"
	}
	dialer := *websocket.DefaultDialer
	if transport, ok := client.Transport.(*http.Transport); ok {
		dialer.TLSClientConfig = transport.TLSClientConfig
	}
	dialer.HandshakeTimeout = 15 * time.Second
	for {
		if lease.Err() != nil {
			return lease.Err()
		}
		connection, response, err := dialer.DialContext(lease, base.String(), http.Header{"Authorization": []string{"Bearer " + enrollment.RuntimeToken}})
		if err != nil && response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if response != nil && (response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 410) {
			return ErrLeaseEnded
		}
		if err == nil {
			connection.SetReadLimit(2 << 20)
			_ = Serve(lease, &WebSocketConn{Conn: connection}, ExecutorConfig{HostKey: signer, ClientKey: key, Username: cfg.Username, Directory: cfg.Directory})
			_ = connection.Close()
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-lease.Done():
			timer.Stop()
			return lease.Err()
		case <-timer.C:
		}
	}
}
func enroll(ctx context.Context, cfg ClientConfig, base *url.URL, client *http.Client) (clientState, error) {
	var zero clientState
	token, err := base64.RawURLEncoding.DecodeString(cfg.EnrollmentToken)
	if err != nil || len(token) != 32 {
		return zero, errors.New("a one-use enrollment token is required")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return zero, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return zero, err
	}
	body, _ := json.Marshal(EnrollmentRequest{HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), Username: cfg.Username, Platform: clientPlatform()})
	request, err := http.NewRequestWithContext(ctx, "POST", base.String()+"/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	request.Header.Set("Authorization", "Bearer "+cfg.EnrollmentToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return zero, errors.New("could not reach the enrollment service")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != 429 {
			return zero, ErrLeaseEnded
		}
		return zero, fmt.Errorf("enrollment temporarily unavailable (HTTP %d)", response.StatusCode)
	}
	var enrollment Enrollment
	if err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&enrollment); err != nil {
		return zero, errors.New("invalid enrollment response")
	}
	if enrollment.LeaseSeconds < 300 || enrollment.LeaseSeconds > 604800 {
		return zero, errors.New("invalid lease duration")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(enrollment.ClientPublicKey)); err != nil {
		return zero, errors.New("invalid platform identity")
	}
	runtimeToken, err := base64.RawURLEncoding.DecodeString(enrollment.RuntimeToken)
	if err != nil || len(runtimeToken) != 32 {
		return zero, errors.New("invalid connection credential")
	}
	if enrollment.ExpiresAt.IsZero() || !time.Now().Before(enrollment.ExpiresAt) {
		return zero, ErrLeaseEnded
	}
	return clientState{ServerURL: cfg.ServerURL, Username: cfg.Username, Directory: cfg.Directory, PrivateKey: private, Enrollment: enrollment}, nil
}

func loadClientState(ctx context.Context, cfg ClientConfig) (clientState, bool, error) {
	var state clientState
	if cfg.StateFile == "" {
		return state, false, nil
	}
	info, err := os.Lstat(cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if !info.Mode().IsRegular() || !privateStateFile(cfg.StateFile, info) || info.Size() > 32<<10 {
		return state, false, fmt.Errorf("%w: unsafe reconnect state", ErrLeaseEnded)
	}
	cipher, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		return state, false, err
	}
	plain, err := cryptClientState(ctx, false, cipher)
	if err != nil {
		return state, false, fmt.Errorf("%w: encrypted identity could not be opened", ErrLeaseEnded)
	}
	if json.Unmarshal(plain, &state) != nil || state.ServerURL != cfg.ServerURL || state.Username != cfg.Username || state.Directory != cfg.Directory || len(state.PrivateKey) != ed25519.PrivateKeySize {
		return state, false, fmt.Errorf("%w: reconnect identity mismatch", ErrLeaseEnded)
	}
	return state, true, nil
}
func saveClientState(ctx context.Context, name string, state clientState) error {
	plain, err := json.Marshal(state)
	if err != nil {
		return err
	}
	cipher, err := cryptClientState(ctx, true, plain)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(name), ".state-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(cipher)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, name)
}
