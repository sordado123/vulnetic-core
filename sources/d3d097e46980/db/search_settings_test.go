package db

import (
	"context"
	"testing"
)

func TestResearchRequiresExplicitAccount(t *testing.T) {
	d := &DB{}
	if _, err := d.SearchConfig(); err == nil {
		t.Fatal("missing account accepted")
	}
	if _, err := d.SaveSearchConfig(context.Background(), AccountSearchPatch{}); err == nil {
		t.Fatal("unscoped save accepted")
	}
	for _, backend := range []string{"mwmbl", "ddgs", "tavily", "exa", "linkup"} {
		if !validSearchBackend(backend) {
			t.Fatalf("supported provider rejected: %s", backend)
		}
	}
	for _, backend := range []string{"", "deepseek", "https://example.org", "shell"} {
		if validSearchBackend(backend) {
			t.Fatalf("unsupported provider accepted: %s", backend)
		}
	}
}

func TestResearchFallbackRequiresExplicitConfiguredProviders(t *testing.T) {
	for _, test := range []struct {
		c     AccountSearchConfig
		valid bool
	}{
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"ddgs"}}, true},
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"tavily"}}, false},
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"tavily"}, TavilyKey: "fixture"}, true},
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"ddgs", "ddgs"}}, false},
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"mwmbl"}}, false},
		{AccountSearchConfig{Backend: "mwmbl", Fallbacks: []string{"https://example.test"}}, false},
	} {
		if validSearchFallbacks(test.c) != test.valid {
			t.Fatalf("invalid validation result for %+v", test.c.Fallbacks)
		}
	}
}
