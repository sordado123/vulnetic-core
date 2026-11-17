package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBetaLLMTransportCannotFallBackToLocal(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer server.Close()
	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Get(server.URL); err == nil {
		t.Fatal("request without verified VPS was accepted")
	}
	if called {
		t.Fatal("customer request reached a local endpoint")
	}
}
