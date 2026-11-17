package cveintel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(s string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(s))}
}
func TestCVEIntelligencePreservesApplicabilityAndSourceState(t *testing.T) {
	c := NewClient("")
	calls := 0
	c.httpClient.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var q osvQueryBody
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		if q.Package.Ecosystem != "npm" || q.Package.Name != "fixture" || q.Version != "1.2.3" {
			t.Fatal("query identity changed", q)
		}
		if calls == 1 {
			return reply(`{"vulns":[{"id":"GHSA-fixture","aliases":["CVE-2025-12345"],"modified":"2025-02-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"fixture"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.4"}]}]}]}],"next_page_token":"next"}`), nil
		}
		if q.PageToken != "next" {
			t.Fatal("pagination missing")
		}
		return reply(`{"vulns":[{"id":"CVE-2025-99999","withdrawn":"2025-01-01T00:00:00Z"}]}`), nil
	})
	got, err := c.QueryOSV(t.Context(), "npm", "fixture", "1.2.3")
	if err != nil || len(got) != 1 || calls != 2 {
		t.Fatalf("%v %v %d", got, err, calls)
	}
	if len(got[0].Affected) != 1 || len(got[0].Aliases) != 2 || got[0].MatchBasis != "package_version" || got[0].Applicability != "requires_context" || got[0].FetchedAt.IsZero() {
		t.Fatal("lost source context", got)
	}
}
func TestCVEPackageRequiresExplicitIdentity(t *testing.T) {
	for _, q := range []PackageQuery{{Name: "nginx", Version: "1.2"}, {PURL: "https://fixture.invalid", Version: "1"}, {Name: "fixture", Ecosystem: "npm"}, {Name: "fixture", Ecosystem: "npm", Version: "1", Commit: "abc"}, {PURL: "pkg:npm/fixture@1", Version: "1"}} {
		if q.Validate() == nil {
			t.Fatal("ambiguous package accepted", q)
		}
	}
	for _, q := range []PackageQuery{{Name: "fixture", Ecosystem: "npm", Version: "1"}, {PURL: "pkg:npm/fixture@1"}, {Name: "fixture", Ecosystem: "npm", Commit: "abc"}} {
		if err := q.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCVENVDUsesCPEAndHonestKeywordFallback(t *testing.T) {
	c := NewClient("")
	c.nvdInterval = -1
	calls := 0
	c.httpClient.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Query().Get("cpeName") == "" {
			t.Fatal("CPE filter missing")
		}
		if calls == 1 {
			return reply(`{"totalResults":2,"startIndex":0,"vulnerabilities":[{"cve":{"id":"CVE-2025-12345","vulnStatus":"Analyzed","configurations":[{"nodes":[{"operator":"AND"}]}],"metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/fixture"}}]}}}]}`), nil
		}
		if r.URL.Query().Get("startIndex") != "1" {
			t.Fatal("NVD page missing")
		}
		return reply(`{"totalResults":2,"startIndex":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-99999","vulnStatus":"Rejected"}}]}`), nil
	})
	got, err := c.QueryCPE(t.Context(), "cpe:2.3:a:vendor:fixture:1:*:*:*:*:*:*:*")
	if err != nil || len(got) != 1 || got[0].MatchBasis != "cpe" || len(got[0].CVSS) != 1 || len(got[0].Affected) != 1 {
		t.Fatal(got, err)
	}
	c.httpClient.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("keywordSearch") != "Fixture + Plus 1.0" {
			t.Fatal("keyword escaping", r.URL)
		}
		return reply(`{"vulnerabilities":[{"cve":{"id":"CVE-2025-12345"}}]}`), nil
	})
	got, err = c.QueryNVD(t.Context(), "Fixture + Plus", "1.0")
	if err != nil || got[0].Applicability != "unknown" || got[0].MatchBasis != "keyword" {
		t.Fatal(got, err)
	}
}
func TestCVESourceFailureIsNotEmptySuccess(t *testing.T) {
	c := NewClient("")
	c.httpClient.Transport = fixtureTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("fixture disconnected") })
	if _, err := c.QueryOSV(t.Context(), "npm", "fixture", "1"); err == nil {
		t.Fatal("outage hidden")
	}
	c.httpClient.Transport = fixtureTransport(func(*http.Request) (*http.Response, error) { return reply(`{"next_page_token":"same"}`), nil })
	if _, err := c.QueryOSV(t.Context(), "npm", "fixture", "1"); err == nil {
		t.Fatal("repeated cursor accepted")
	}
	c.nvdLastCall = time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.rateLimitNVD(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("rate limit ignored cancellation", err)
	}
}
func TestCVEPriorityZeroIsKnownOnlyWhenSourceReportedIt(t *testing.T) {
	c := NewClient("")
	c.httpClient.Transport = fixtureTransport(func(*http.Request) (*http.Response, error) {
		return reply(`{"data":[{"cve":"CVE-2025-12345","epss":"0","percentile":"0","date":"2025-01-01"},{"cve":"CVE-2025-99999","epss":"NaN","percentile":"0.1"}]}`), nil
	})
	got, err := c.QueryEPSS(t.Context(), []string{"CVE-2025-12345"})
	if err != nil || len(got) != 1 || got["CVE-2025-12345"].Date != "2025-01-01" {
		t.Fatal(got, err)
	}
}
func TestCVEDedupPreservesAliasesAndSources(t *testing.T) {
	got := MergeCandidates([]Candidate{{CVEID: "GHSA-fixture", Aliases: []string{"CVE-2025-12345"}, Source: "osv", MatchBasis: "package_version", Applicability: "requires_context"}, {CVEID: "CVE-2025-12345", Source: "nvd", MatchBasis: "keyword", Applicability: "unknown"}})
	if len(got) != 1 || len(got[0].Sources) != 2 || got[0].CVEID != "CVE-2025-12345" || got[0].MatchBasis != "package_version" {
		t.Fatal(got)
	}
}

func TestCVEDedupMergesAliasBridgeRegardlessOfOrder(t *testing.T) {
	a := Candidate{CVEID: "GHSA-first", Source: "osv", Summary: "Original source"}
	b := Candidate{CVEID: "CVE-2025-12345", Source: "nvd"}
	bridge := Candidate{CVEID: "GHSA-bridge", Aliases: []string{a.CVEID, b.CVEID}, Source: "vendor"}
	for _, rows := range [][]Candidate{{a, b, bridge}, {bridge, a, b}, {b, bridge, a}} {
		got := MergeCandidates(rows)
		if len(got) != 1 || len(got[0].Aliases) != 3 || len(got[0].Sources) != 3 || got[0].Summary != "Original source" {
			t.Fatalf("alias bridge was not consolidated: %+v", got)
		}
	}
}
