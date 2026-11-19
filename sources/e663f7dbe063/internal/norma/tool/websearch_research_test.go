package tool

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type researchRoundTrip func(*http.Request) (*http.Response, error)

func (f researchRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResearchUsesInjectedTransport(t *testing.T) {
	for _, backend := range []string{"mwmbl", "ddgs", "tavily", "exa", "linkup"} {
		t.Run(backend, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: researchRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" {
					t.Fatal("search must use HTTPS")
				}
				if backend == "mwmbl" && (r.Method != "GET" || r.Body != nil || r.URL.Query().Get("q") != "CVE research") {
					t.Fatal("invalid Mwmbl query")
				}
				if backend == "exa" && r.Header.Get("x-api-key") != "exa-fixture" {
					t.Fatal("missing Exa authentication")
				}
				if backend == "linkup" && r.Header.Get("Authorization") != "Bearer linkup-fixture" {
					t.Fatal("missing Linkup authentication")
				}
				return &http.Response{StatusCode: 429, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("quota")), Request: r}, nil
			})}
			_, err := WebSearchProbe(context.Background(), WebSearchConfig{Backend: backend, HTTPClient: client, TavilyAPIKey: "tavily-fixture", ExaAPIKey: "exa-fixture", LinkupAPIKey: "linkup-fixture"}, "CVE research", 5)
			if err == nil || calls != 1 {
				t.Fatalf("quota must fail without fallback: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestResearchResultFormats(t *testing.T) {
	for _, fixture := range []string{
		` {"results":[{"url":"https://example.org/advisory","title":[{"value":"Vendor "},{"value":"advisory"}],"extract":[{"value":"CVE details"}]}]} `,
		`[{"url":"https://example.org/advisory","title":"Vendor advisory","highlights":["CVE details"]}]`,
		`{"results":[{"url":"https://example.org/advisory","name":"Vendor advisory","content":"CVE details"}]}`,
	} {
		results, err := parseResearchResults([]byte(fixture), 1)
		if err != nil || len(results) != 1 || results[0].Title != "Vendor advisory" || results[0].Description != "CVE details" {
			t.Fatalf("unexpected results: %+v %v", results, err)
		}
	}
	results, err := parseResearchResults([]byte(`{"results":[{"url":"file:///secret"},{"url":"https://user:password@example.org/"},{"url":"javascript:alert(1)"}]}`), 5)
	if err != nil || len(results) != 0 {
		t.Fatal("unsafe result URLs must be omitted")
	}
	if _, err = parseResearchResults([]byte(`{"error":"quota"}`), 5); err == nil {
		t.Fatal("invalid responses must not look like empty results")
	}
}
