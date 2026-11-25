package server

import (
	"bytes"
	"compress/gzip"
	"github.com/sordado123/vulnetic/agent"
	"net/http"
	"strings"
	"testing"
)

func TestSavedKeyDestinationBoundary(t *testing.T) {
	if !sameLLMKeyDestination("OPENAI", "https://provider.example/v1/chat/completions", "", "openai", "https://provider.example/v1/", "") {
		t.Fatal("equivalent destination rejected")
	}
	for _, c := range []struct{ provider, base, proxy string }{{"anthropic", "https://provider.example/v1", ""}, {"openai", "https://other.example/v1", ""}, {"openai", "https://provider.example/v1", "http://proxy.example"}, {"openai", "http://provider.example/v1", ""}} {
		if sameLLMKeyDestination(c.provider, c.base, c.proxy, "openai", "https://provider.example/v1", "") {
			t.Fatal("saved key crossed destination boundary", c)
		}
	}
	origin, _ := http.NewRequest("GET", "https://provider.example/v1", nil)
	other, _ := http.NewRequest("GET", "https://sub.provider.example/v1", nil)
	if agent.LLMRedirectPolicy(other, []*http.Request{origin}) == nil {
		t.Fatal("cross-origin credentials permitted")
	}
}
func TestEvidenceQuoteIsAdvisoryAndBounded(t *testing.T) {
	if !quotePresent("prefix observed\n  execution result suffix", "observed execution result") {
		t.Fatal("normalized quote not found")
	}
	if quotePresent("unrelated output", "observed execution result") || quotePresent("short", "short") {
		t.Fatal("unsubstantiated quote accepted")
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, _ = gz.Write([]byte("recorded execution result"))
	_ = gz.Close()
	body, err := boundedEvidenceBody(&b, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip")
	if err != nil || !quotePresent(string(body), "recorded execution") {
		t.Fatal("gzip evidence not read", err)
	}
	if _, err = boundedEvidenceBody(strings.NewReader(strings.Repeat("x", (1<<20)+1)), ""); err == nil {
		t.Fatal("unbounded body accepted")
	}
	if _, err = boundedEvidenceBody(strings.NewReader("encoded"), "HTTP/1.1 200 OK\r\nContent-Encoding: unsupported"); err == nil {
		t.Fatal("unsupported encoding assessed")
	}
}
