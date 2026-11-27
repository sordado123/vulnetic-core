package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Gateway and application have different environments in production; never share the application's admission settings or DB credentials.
func gatewayFixtureProcess(t *testing.T, tokenFile string) (string, string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run", "^TestGatewayHTTPProcessHelper$", "-test.timeout", "3m")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "VULNETIC_PG_") || strings.HasPrefix(key, "ARTEX_PG_") || key == "VULNETIC_SAAS_MODE" || key == "VULNETIC_GATEWAY_TOKEN_FILE" || key == "VULNETIC_GATEWAY_FIXTURE_PROCESS" {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "VULNETIC_SAAS_MODE=false", "VULNETIC_GATEWAY_TOKEN_FILE="+tokenFile, "VULNETIC_GATEWAY_FIXTURE_PROCESS=1")
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "GATEWAY_FIXTURE_READY=") {
				ready <- strings.TrimPrefix(scanner.Text(), "GATEWAY_FIXTURE_READY=")
				return
			}
		}
		ready <- ""
	}()
	select {
	case raw := <-ready:
		var urls struct{ Private, Public string }
		if err = json.Unmarshal([]byte(raw), &urls); err != nil || urls.Private == "" || urls.Public == "" {
			t.Fatal("isolated gateway did not start", err)
		}
		return urls.Private, urls.Public
	case <-time.After(15 * time.Second):
		t.Fatal("isolated gateway startup timed out")
	}
	return "", ""
}
func TestGatewayHTTPProcessHelper(t *testing.T) {
	if os.Getenv("VULNETIC_GATEWAY_FIXTURE_PROCESS") != "1" {
		t.Skip("subprocess helper only")
	}
	raw, err := os.ReadFile(os.Getenv("VULNETIC_GATEWAY_TOKEN_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := agentgateway.New(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	private := httptest.NewServer(g.PrivateHandler())
	defer private.Close()
	public := httptest.NewServer(g.PublicHandler())
	defer public.Close()
	urls, _ := json.Marshal(map[string]string{"Private": private.URL, "Public": public.URL})
	fmt.Printf("GATEWAY_FIXTURE_READY=%s\n", urls)
	<-t.Context().Done()
}
