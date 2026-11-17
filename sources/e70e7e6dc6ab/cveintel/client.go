// Package cveintel talks to external CVE intelligence sources (OSV.dev, NVD,
// FIRST.org EPSS, CISA KEV) on behalf of the lookup_cve agent tool. It never
// touches Postgres and never knows about the exploration graph â€” callers
// (agent/tools_cve.go) own caching and persistence. This client never routes
// through the target-traffic recording proxy: it talks to CVE databases, not
// to a penetration-test target.
package cveintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Candidate is one CVE candidate, in the shared shape both OSV and NVD get
// normalized into. EPSS/KEV fields are filled in by a later enrichment pass
// (agent/tools_cve.go), not by QueryOSV/QueryNVD themselves â€” zero values
// mean "not checked yet", not "not exploited".

// permanentErr marks an error that retrying will not fix (bad input, a 4xx
// that is not rate-limiting). Mirrors notify.Permanent, kept local so this
// package does not import an unrelated domain just for one helper.
type permanentErr struct{ err error }

func (p *permanentErr) Error() string { return p.err.Error() }
func (p *permanentErr) Unwrap() error { return p.err }

func permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentErr{err}
}

// IsPermanent reports whether err was wrapped by permanent() â€” i.e. retrying
// the same request is pointless.
func IsPermanent(err error) bool {
	_, ok := err.(*permanentErr)
	return ok
}

// respBodyLimit caps every response this package reads. OSV/NVD/EPSS replies
// are small (tens of KB); the CISA KEV catalog (kev.go) is the outlier at a
// few MB, so the shared limit is sized for that, not for the common case.
const respBodyLimit = 8 << 20

// Client queries the external CVE sources. The zero value is not usable;
// construct with NewClient.
type Client struct {
	httpClient *http.Client
	nvdAPIKey  string

	nvdMu       sync.Mutex // serializes NVD calls so the rate gate below is meaningful across concurrent workers
	nvdLastCall time.Time
	nvdInterval time.Duration
}

// NewClient builds a client isolated from the target-traffic proxy, with a
// short timeout (these are small JSON APIs, not binary downloads) and a
// same-host-only redirect policy. nvdAPIKey may be empty â€” NVD is then called
// unauthenticated, under the public rate limit (see nvdMinInterval).
func NewClient(nvdAPIKey string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &Client{
		nvdAPIKey: nvdAPIKey,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("refusing cross-host redirect (%s â†’ %s)", via[0].URL.Host, req.URL.Host)
				}
				return nil
			},
		},
	}
}

// doRequest sends one request and classifies the outcome the same way
// notify/http.go's doJSON does: network errors and 5xx/429/408 are retryable,
// the remaining 4xx are permanent() (retrying a 400/404 just repeats it).
func (c *Client) doRequest(ctx context.Context, method, url string, headers map[string]string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, permanent(fmt.Errorf("invalid request: %w", err))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", hostOf(url), err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit+1))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response from %s: %w", hostOf(url), readErr)
	}
	if len(raw) > respBodyLimit {
		return nil, fmt.Errorf("response from %s exceeds limit", hostOf(url))
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("%s rate-limited or timed out (HTTP %d)", hostOf(url), resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("%s server error (HTTP %d)", hostOf(url), resp.StatusCode)
	}
	return nil, permanent(fmt.Errorf("%s rejected the request (HTTP %d): %s", hostOf(url), resp.StatusCode, snippet(raw)))
}

func hostOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return rawURL
}

func snippet(b []byte) string {
	const max = 300
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "â€¦"
	}
	return s
}

// --- OSV.dev ---

type osvQueryBody struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	PageToken string `json:"page_token,omitempty"`
	Package   struct {
		Name      string `json:"name,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvVuln struct {
	Published  string            `json:"published"`
	Modified   string            `json:"modified"`
	Withdrawn  string            `json:"withdrawn"`
	Affected   []json.RawMessage `json:"affected"`
	ID         string            `json:"id"`
	Summary    string            `json:"summary"`
	Details    string            `json:"details"`
	Aliases    []string          `json:"aliases"`
	Severity   []osvSeverity     `json:"severity"`
	References []osvReference    `json:"references"`
}

type osvResponse struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token"`
}

// QueryOSV queries https://api.osv.dev/v1/query for a (ecosystem, package,
// version) triple. No API key needed. OSV is strong for language-ecosystem
// packages (npm/PyPI/Go/crates/Maven) and OS packages (ecosystem=Debian/
// Alpine/...); it is weak for edge/infra software fingerprinted only by an
// HTTP banner â€” that gap is exactly why QueryNVD exists as a fallback.
func (c *Client) QueryOSV(ctx context.Context, ecosystem, product, version string) ([]Candidate, error) {
	return c.QueryPackage(ctx, PackageQuery{Ecosystem: ecosystem, Name: product, Version: version})
}
func (c *Client) QueryPackage(ctx context.Context, q PackageQuery) ([]Candidate, error) {
	if err := q.Validate(); err != nil {
		return nil, permanent(err)
	}
	body := osvQueryBody{Version: q.Version, Commit: q.Commit}
	body.Package.Name = q.Name
	body.Package.Ecosystem = q.Ecosystem
	body.Package.PURL = q.PURL
	var out []Candidate
	seenPages := map[string]bool{}
	for page := 0; page < 20; page++ {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw, err := c.doRequest(ctx, http.MethodPost, "https://api.osv.dev/v1/query", map[string]string{"Content-Type": "application/json"}, data)
		if err != nil {
			return nil, err
		}
		var parsed osvResponse
		if err = json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("osv.dev: malformed response: %w", err)
		}
		for _, v := range parsed.Vulns {
			if v.Withdrawn != "" {
				continue
			}
			cand := Candidate{CVEID: extractCVEID(v.ID, v.Aliases), Aliases: append([]string{v.ID}, v.Aliases...), Summary: firstNonEmpty(v.Summary, v.Details), Source: "osv", Sources: []string{"osv"}, MatchBasis: "package_version", Applicability: "requires_context", Affected: v.Affected, Published: v.Published, Modified: v.Modified, FetchedAt: time.Now().UTC()}
			if q.Commit != "" {
				cand.MatchBasis = "package_commit"
			}
			for _, sev := range v.Severity {
				cand.CVSS = append(cand.CVSS, CVSS{Version: sev.Type, Vector: sev.Score, Source: "osv"})
				if cand.Severity == "" {
					cand.Severity = sev.Score
				}
			}
			for _, ref := range v.References {
				cand.References = append(cand.References, ref.URL)
			}
			out = append(out, cand)
		}
		if parsed.NextPageToken == "" {
			return MergeCandidates(out), nil
		}
		if seenPages[parsed.NextPageToken] {
			return nil, fmt.Errorf("osv.dev: repeated pagination cursor")
		}
		seenPages[parsed.NextPageToken] = true
		body.PageToken = parsed.NextPageToken
	}
	return nil, fmt.Errorf("osv.dev: result pagination limit reached; query incomplete")
}

// extractCVEID prefers a CVE-shaped alias (OSV's own id is often a GHSA/PYSEC/
// etc. id, with the matching CVE listed as an alias); falls back to the OSV
// id itself when nothing CVE-shaped is found, so the caller still gets a
// stable identifier to cite.
func extractCVEID(osvID string, aliases []string) string {
	if isCVEID(osvID) {
		return osvID
	}
	for _, a := range aliases {
		if isCVEID(a) {
			return a
		}
	}
	return osvID
}

func isCVEID(s string) bool {
	return strings.HasPrefix(strings.ToUpper(s), "CVE-")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- NVD (keyword fallback) ---

const nvdMinInterval = 6 * time.Second // ~5 req/30s public ceiling without an API key, with margin

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

type nvdMetrics struct {
	CvssMetricV40 []struct {
		CvssData nvdCVSSData `json:"cvssData"`
		Source   string      `json:"source"`
	} `json:"cvssMetricV40"`
	CvssMetricV31 []struct {
		CvssData nvdCVSSData `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV30 []struct {
		CvssData nvdCVSSData `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CvssMetricV2 []struct {
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdCVE struct {
	VulnStatus     string            `json:"vulnStatus"`
	Published      string            `json:"published"`
	LastModified   string            `json:"lastModified"`
	Configurations []json.RawMessage `json:"configurations"`
	ID             string            `json:"id"`
	Descriptions   []nvdDescription  `json:"descriptions"`
	Metrics        nvdMetrics        `json:"metrics"`
	References     []nvdReference    `json:"references"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdResponse struct {
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
	TotalResults    int                `json:"totalResults"`
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
}

// QueryNVD does a free-text keywordSearch against NVD 2.0 for "<product>
// <version>" â€” deliberately not CPE matching, which needs an exact CPE
// string we do not reliably have from a free-text fingerprint. This trades
// precision for simplicity; treat results as softer leads than OSV's.
func (c *Client) QueryNVD(ctx context.Context, product, version string) ([]Candidate, error) {
	return c.queryNVD(ctx, url.Values{"keywordSearch": {strings.TrimSpace(product + " " + version)}}, "keyword")
}
func (c *Client) QueryCPE(ctx context.Context, cpe string) ([]Candidate, error) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") || len(cpe) > 2048 || len(strings.Split(cpe, ":")) < 13 {
		return nil, permanent(fmt.Errorf("an explicit CPE 2.3 name is required"))
	}
	return c.queryNVD(ctx, url.Values{"cpeName": {cpe}}, "cpe")
}
func (c *Client) queryNVD(ctx context.Context, query url.Values, basis string) ([]Candidate, error) {
	var out []Candidate
	query.Set("resultsPerPage", "100")
	for page := 0; page < 20; page++ {
		if err := c.rateLimitNVD(ctx); err != nil {
			return nil, err
		}
		headers := map[string]string{}
		if c.nvdAPIKey != "" {
			headers["apiKey"] = c.nvdAPIKey
		}
		raw, err := c.doRequest(ctx, http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0?"+query.Encode(), headers, nil)
		if err != nil {
			return nil, err
		}
		var parsed nvdResponse
		if err = json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("nvd: malformed response: %w", err)
		}
		for _, v := range parsed.Vulnerabilities {
			if strings.EqualFold(v.CVE.VulnStatus, "Rejected") {
				continue
			}
			cand := Candidate{CVEID: v.CVE.ID, Aliases: []string{v.CVE.ID}, Source: "nvd", Sources: []string{"nvd"}, MatchBasis: basis, Applicability: "unknown", Affected: v.CVE.Configurations, Published: v.CVE.Published, Modified: v.CVE.LastModified, FetchedAt: time.Now().UTC()}
			if basis == "cpe" {
				cand.Applicability = "requires_context"
			}
			for _, d := range v.CVE.Descriptions {
				if d.Lang == "en" {
					cand.Summary = d.Value
					break
				}
			}
			add := func(d nvdCVSSData, version string) {
				score := d.BaseScore
				cand.CVSS = append(cand.CVSS, CVSS{Version: version, Vector: d.VectorString, Score: &score, Severity: d.BaseSeverity, Source: "nvd"})
				if cand.Severity == "" {
					cand.Severity = d.BaseSeverity
				}
			}
			for _, v := range v.CVE.Metrics.CvssMetricV40 {
				add(v.CvssData, "4.0")
			}
			for _, v := range v.CVE.Metrics.CvssMetricV31 {
				add(v.CvssData, "3.1")
			}
			for _, v := range v.CVE.Metrics.CvssMetricV30 {
				add(v.CvssData, "3.0")
			}
			for _, v := range v.CVE.Metrics.CvssMetricV2 {
				score := v.CvssData.BaseScore
				cand.CVSS = append(cand.CVSS, CVSS{Version: "2.0", Score: &score, Severity: v.BaseSeverity, Source: "nvd"})
				if cand.Severity == "" {
					cand.Severity = v.BaseSeverity
				}
			}
			for _, ref := range v.CVE.References {
				cand.References = append(cand.References, ref.URL)
			}
			out = append(out, cand)
		}
		next := parsed.StartIndex + len(parsed.Vulnerabilities)
		if next >= parsed.TotalResults {
			return MergeCandidates(out), nil
		}
		if len(parsed.Vulnerabilities) == 0 {
			return nil, fmt.Errorf("nvd: incomplete pagination")
		}
		query.Set("startIndex", strconv.Itoa(next))
	}
	return nil, fmt.Errorf("nvd: result pagination limit reached; query incomplete")
}
func (c *Client) rateLimitNVD(ctx context.Context) error {
	for {
		c.nvdMu.Lock()
		interval := c.nvdInterval
		if interval == 0 {
			interval = nvdMinInterval
		}
		wait := interval - time.Since(c.nvdLastCall)
		if wait <= 0 {
			c.nvdLastCall = time.Now()
			c.nvdMu.Unlock()
			return ctx.Err()
		}
		c.nvdMu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// --- EPSS ---

type EPSSScore struct {
	Score      float64
	Date       string
	Percentile float64
}

type epssDatum struct {
	Date       string `json:"date"`
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

type epssResponse struct {
	Data []epssDatum `json:"data"`
}

// QueryEPSS fetches exploitation-probability scores for up to ~100 CVE ids in
// one call (the API accepts a comma-joined list). No API key needed.
func (c *Client) QueryEPSS(ctx context.Context, cveIDs []string) (map[string]EPSSScore, error) {
	out := map[string]EPSSScore{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	url := "https://api.first.org/data/v1/epss?cve=" + urlQueryEscape(strings.Join(cveIDs, ","))
	raw, err := c.doRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}
	var parsed epssResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("epss: malformed response: %w", err)
	}
	for _, d := range parsed.Data {
		score, e1 := strconv.ParseFloat(d.EPSS, 64)
		pct, e2 := strconv.ParseFloat(d.Percentile, 64)
		if e1 != nil || e2 != nil || math.IsNaN(score) || math.IsNaN(pct) || score < 0 || score > 1 || pct < 0 || pct > 1 {
			continue
		}
		out[strings.ToUpper(d.CVE)] = EPSSScore{Score: score, Percentile: pct, Date: d.Date}
	}
	return out, nil
}
