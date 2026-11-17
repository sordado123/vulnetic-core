package agentassets

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsForegroundDistribution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VULNETIC_AGENT_BINARY_DIR", dir)
	content := []byte("foreground fixture")
	if err := os.WriteFile(filepath.Join(dir, "windows-amd64.exe"), content, 0600); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		handler http.HandlerFunc
		want    string
	}{{Binary, string(content)}, {Checksum, fmt.Sprintf("%x  agent\n", sha256.Sum256(content))}} {
		r := httptest.NewRequest("GET", "/agent/binary/windows-amd64", nil)
		r.SetPathValue("arch", "windows-amd64")
		w := httptest.NewRecorder()
		check.handler(w, r)
		if w.Code != http.StatusOK || w.Body.String() != check.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Windows foreground download failed: %d %q", w.Code, w.Body.String())
		}
	}
}

func TestLinuxExecutorDistributionStillAvailable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VULNETIC_AGENT_BINARY_DIR", dir)
	content := []byte("approved Linux fixture")
	for _, arch := range []string{"amd64", "arm64"} {
		if err := os.WriteFile(filepath.Join(dir, "linux-"+arch), content, 0600); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			handler http.HandlerFunc
			want    string
		}{{Binary, string(content)}, {Checksum, fmt.Sprintf("%x  agent\n", sha256.Sum256(content))}} {
			r := httptest.NewRequest("GET", "/agent/binary/"+arch, nil)
			r.SetPathValue("arch", arch)
			w := httptest.NewRecorder()
			check.handler(w, r)
			if w.Code != http.StatusOK || w.Body.String() != check.want {
				t.Fatalf("Linux %s changed: %d %q", arch, w.Code, w.Body.String())
			}
		}
	}
}
