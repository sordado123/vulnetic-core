package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sordado123/vulnetic/agent"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/internal/runstate"
	"github.com/sordado123/vulnetic/sshexec"
)

var referenceCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,12}$`)

type cvePublicReference struct {
	URL     string   `json:"url"`
	Title   string   `json:"title,omitempty"`
	Kind    string   `json:"kind"`
	Sources []string `json:"sources"`
}

type cveReferenceRecord struct {
	CVEID       string            `json:"cve_id"`
	State       string            `json:"state,omitempty"`
	Source      string            `json:"source"`
	Summary     string            `json:"summary,omitempty"`
	Affected    []json.RawMessage `json:"affected,omitempty"`
	PublishedAt string            `json:"published_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	Notice      string            `json:"notice"`
}

type cveReferenceData struct {
	References []cvePublicReference
	Record     *cveReferenceRecord
	FetchedAt  time.Time
	ExpiresAt  time.Time
}

type cveReferenceKey struct {
	Account, Executor int64
	CVE, Source       string
}

// shortcut: bounded process-local cache; a restart safely refetches public metadata.
type cveReferenceCache struct {
	mu      sync.Mutex
	entries map[cveReferenceKey]cveReferenceData
	backoff map[cveReferenceKey]time.Time
	pending map[cveReferenceKey]*cveReferenceFlight
}

type cveReferenceFlight struct {
	done  chan struct{}
	value cveReferenceData
	err   error
}

func (c *cveReferenceCache) load(ctx context.Context, key cveReferenceKey, fetch func() (cveReferenceData, error)) (cveReferenceData, bool, error) {
	if value, ok, delay := c.get(key); ok {
		return value, true, nil
	} else if delay > 0 {
		return value, false, &actool.ResearchFailure{Code: "provider_rate_limited", RetryAfter: delay}
	}
	c.mu.Lock()
	if prior := c.pending[key]; prior != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return cveReferenceData{}, false, ctx.Err()
		case <-prior.done:
			return prior.value, true, prior.err
		}
	}
	if c.pending == nil {
		c.pending = make(map[cveReferenceKey]*cveReferenceFlight)
	}
	flight := &cveReferenceFlight{done: make(chan struct{})}
	c.pending[key] = flight
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, key); close(flight.done); c.mu.Unlock() }()
	value, cached, delay := c.get(key)
	var err error
	if delay > 0 {
		err = &actool.ResearchFailure{Code: "provider_rate_limited", RetryAfter: delay}
	} else if !cached {
		value, err = fetch()
	}
	if err == nil && !cached {
		c.put(key, value, 0)
	}
	var failure *actool.ResearchFailure
	if errors.As(err, &failure) && failure.RetryAfter > 0 {
		c.put(key, cveReferenceData{}, failure.RetryAfter)
	}
	flight.value, flight.err = value, err
	return value, cached, err
}

func (c *cveReferenceCache) get(key cveReferenceKey) (cveReferenceData, bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if value, ok := c.entries[key]; ok && time.Now().Before(value.ExpiresAt) {
		return value, true, 0
	}
	key.CVE = ""
	return cveReferenceData{}, false, max(time.Until(c.backoff[key]), 0)
}

func (c *cveReferenceCache) put(key cveReferenceKey, value cveReferenceData, delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[cveReferenceKey]cveReferenceData)
		c.backoff = make(map[cveReferenceKey]time.Time)
	}
	if delay > 0 {
		key.CVE = ""
		if len(c.backoff) >= 512 {
			for k, until := range c.backoff {
				if time.Now().After(until) {
					delete(c.backoff, k)
				}
			}
		}
		if len(c.backoff) < 512 {
			c.backoff[key] = time.Now().Add(min(delay, time.Hour))
		}
		return
	}
	if len(c.entries) >= 512 {
		var oldest cveReferenceKey
		var at time.Time
		for k, v := range c.entries {
			if at.IsZero() || v.FetchedAt.Before(at) {
				oldest, at = k, v.FetchedAt
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[key] = value
}

func canonicalCVEReference(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.User != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Host == "github.com" {
		u.Scheme = "https"
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) >= 2 {
			parts[0], parts[1] = strings.ToLower(parts[0]), strings.TrimSuffix(strings.ToLower(parts[1]), ".git")
			u.Path = "/" + strings.Join(parts, "/")
			u.RawPath = ""
		}
		u.RawQuery = ""
	}
	return u.String()
}

func mergeCVEReferences(groups ...[]cvePublicReference) []cvePublicReference {
	out := []cvePublicReference{}
	byURL := map[string]int{}
	for _, group := range groups {
		for _, ref := range group {
			ref.URL = canonicalCVEReference(ref.URL)
			if ref.URL == "" {
				continue
			}
			if i, ok := byURL[ref.URL]; ok {
				for _, source := range ref.Sources {
					found := false
					for _, prior := range out[i].Sources {
						found = found || prior == source
					}
					if !found {
						out[i].Sources = append(out[i].Sources, source)
					}
				}
				continue
			}
			ref.Title = trunc(ref.Title, 300)
			ref.Sources = append([]string{}, ref.Sources...)
			byURL[ref.URL] = len(out)
			out = append(out, ref)
		}
	}
	return out
}

func fetchCVEReferences(ctx context.Context, client *http.Client, source, cve string) (cveReferenceData, error) {
	var endpoint string
	switch source {
	case "poc_in_github":
		endpoint = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/" + cve[4:8] + "/" + cve + ".json"
	case "github_search":
		endpoint = "https://api.github.com/search/repositories?" + url.Values{"q": {cve + " in:name,description,readme fork:false"}, "sort": {"stars"}, "per_page": {"50"}}.Encode()
	case "circl":
		endpoint = "https://vulnerability.circl.lu/api/vulnerability/" + cve
	default:
		return cveReferenceData{}, &actool.ResearchFailure{Code: "not_configured"}
	}
	if err := platformpolicy.CheckHost(endpoint); err != nil {
		return cveReferenceData{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return cveReferenceData{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Vulnetic-CVE-Research/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return cveReferenceData{}, err
	}
	defer resp.Body.Close()
	value := cveReferenceData{References: []cvePublicReference{}, FetchedAt: time.Now().UTC()}
	value.ExpiresAt = value.FetchedAt.Add(6 * time.Hour)
	if resp.StatusCode == 404 && source != "github_search" {
		value.ExpiresAt = value.FetchedAt.Add(10 * time.Minute)
		return value, nil
	}
	if resp.StatusCode != http.StatusOK {
		if source == "github_search" && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			reset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
			return cveReferenceData{}, &actool.ResearchFailure{Code: "provider_rate_limited", RetryAfter: min(max(time.Until(time.Unix(reset, 0)), time.Minute), time.Hour)}
		}
		return cveReferenceData{}, actool.ResearchHTTPError(resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	const sizeLimit = 4 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, sizeLimit+1))
	if err != nil {
		return cveReferenceData{}, err
	}
	if len(raw) > sizeLimit {
		return cveReferenceData{}, &actool.ResearchFailure{Code: "response_too_large"}
	}
	if source == "circl" {
		var row struct {
			Metadata struct {
				ID        string `json:"cveId"`
				State     string `json:"state"`
				Published string `json:"datePublished"`
				Updated   string `json:"dateUpdated"`
			} `json:"cveMetadata"`
			Containers struct {
				CNA struct {
					Title        string `json:"title"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Affected   []json.RawMessage `json:"affected"`
					References []struct {
						URL  string `json:"url"`
						Name string `json:"name"`
					} `json:"references"`
				} `json:"cna"`
			} `json:"containers"`
		}
		if json.Unmarshal(raw, &row) != nil || !strings.EqualFold(row.Metadata.ID, cve) {
			return cveReferenceData{}, &actool.ResearchFailure{Code: "invalid_response"}
		}
		summary := row.Containers.CNA.Title
		for _, description := range row.Containers.CNA.Descriptions {
			if description.Lang == "en" {
				summary = description.Value
				break
			}
		}
		affected := []json.RawMessage{}
		for _, item := range row.Containers.CNA.Affected {
			if len(affected) < 5 && len(item) <= 4096 {
				affected = append(affected, item)
			}
		}
		value.Record = &cveReferenceRecord{CVEID: cve, State: row.Metadata.State, Source: source, Summary: trunc(summary, 1800), Affected: affected, PublishedAt: row.Metadata.Published, UpdatedAt: row.Metadata.Updated, Notice: "Declared affected ranges, possibly truncated; not an observed product/version match or complete coverage."}
		for _, ref := range row.Containers.CNA.References {
			if len(value.References) >= 100 {
				break
			}
			value.References = append(value.References, cvePublicReference{URL: ref.URL, Title: ref.Name, Kind: "cve_reference", Sources: []string{source}})
		}
	} else {
		type repository struct {
			URL   string `json:"html_url"`
			Name  string `json:"full_name"`
			Stars int    `json:"stargazers_count"`
			Fork  bool   `json:"fork"`
		}
		var rows []repository
		if source == "github_search" {
			var response struct {
				Items []repository `json:"items"`
				Total *int         `json:"total_count"`
			}
			if json.Unmarshal(raw, &response) != nil || response.Total == nil {
				return cveReferenceData{}, &actool.ResearchFailure{Code: "invalid_response"}
			}
			rows = response.Items
		} else if json.Unmarshal(raw, &rows) != nil || rows == nil {
			return cveReferenceData{}, &actool.ResearchFailure{Code: "invalid_response"}
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Stars > rows[j].Stars })
		for _, row := range rows {
			u, err := url.Parse(row.URL)
			if row.Fork || err != nil || u.Host != "github.com" || len(strings.Split(strings.Trim(u.Path, "/"), "/")) != 2 {
				continue
			}
			kind := "indexed_poc_reference"
			if source == "github_search" {
				kind = "related_repository"
			}
			value.References = append(value.References, cvePublicReference{URL: row.URL, Title: row.Name, Kind: kind, Sources: []string{source}})
			if len(value.References) >= 50 {
				break
			}
		}
	}
	value.References = mergeCVEReferences(value.References)
	if len(value.References) == 0 && value.Record == nil {
		value.ExpiresAt = value.FetchedAt.Add(10 * time.Minute)
	}
	return value, nil
}

func (s *Server) toolCVEReferences() actool.CoreTool {
	return wrTool("lookup_cve_references", "Find public CVE metadata and indexed PoC/repository references from PoC-in-GitHub, GitHub Search and CIRCL through the selected executor. Cached and deduplicated by account/executor/CVE. Returns untrusted references only, never downloads or executes PoC code, never verifies a finding. Existing lookup_cve and web_search remain available.", objSchema(map[string]any{
		"cve_id": map[string]any{"type": "string", "pattern": "^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,12}$", "maxLength": 32, "description": "One known CVE identifier; not a target URL or a free-text query."},
		"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "description": "Maximum deduplicated references; default 10."},
	}, "cve_id"), func(ctx context.Context, input json.RawMessage) (actool.Result, error) {
		var args struct {
			CVE   string `json:"cve_id"`
			Limit int    `json:"limit"`
		}
		if json.Unmarshal(input, &args) != nil {
			return actool.Errorf("invalid CVE reference parameters"), nil
		}
		args.CVE = strings.ToUpper(strings.TrimSpace(args.CVE))
		if !referenceCVEPattern.MatchString(args.CVE) || args.Limit < 0 || args.Limit > 20 {
			return actool.Errorf("provide one CVE identifier and a limit from 1 to 20"), nil
		}
		if args.Limit == 0 {
			args.Limit = 10
		}
		ri := agent.RunInfoFrom(ctx)
		if ri.AccountID <= 0 {
			return actool.Errorf("authenticated account required"), nil
		}
		ex, ok := ri.Executor.(*sshexec.LazyExecutor)
		if !ok || ex == nil || ri.ExecutorID <= 0 {
			return actool.Errorf("select a connected customer executor for CVE research; local requests are disabled"), nil
		}
		if _, err := s.verifiedTarget(ri.AccountID, ri.ExecutorID); err != nil {
			return actool.Errorf("active connected executor required for CVE research"), nil
		}
		settings, err := s.m.pg.ForAccount(ri.AccountID).SearchConfig()
		if err != nil {
			return actool.Errorf("research configuration unavailable"), nil
		}
		if !settings.Enabled {
			return actool.Errorf("research disabled in account settings"), nil
		}
		ctx, cancel := context.WithTimeout(runstate.TraceHTTP(ctx), 45*time.Second)
		defer cancel()
		transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("research provider redirects are not allowed")
		}}
		attempts := []map[string]any{}
		groups := [][]cvePublicReference{}
		var record *cveReferenceRecord
		completed := 0
		for _, source := range []string{"poc_in_github", "github_search", "circl"} {
			if err := ctx.Err(); err != nil {
				return actool.Errorf(actool.ResearchErrorCode(err)), nil
			}
			host := map[string]string{"poc_in_github": "raw.githubusercontent.com", "github_search": "api.github.com", "circl": "vulnerability.circl.lu"}[source]
			if err := platformpolicy.CheckHost(host); err != nil {
				return actool.Errorf("policy_denied: research source unavailable"), nil
			}
			key := cveReferenceKey{Account: ri.AccountID, Executor: ri.ExecutorID, CVE: args.CVE, Source: source}
			value, cached, fetchErr := s.cveReferences.load(ctx, key, func() (cveReferenceData, error) { return fetchCVEReferences(ctx, client, source, args.CVE) })
			if fetchErr != nil {
				code := actool.ResearchErrorCode(fetchErr)
				entry := map[string]any{"source": source, "status": code, "cached": false}
				var failure *actool.ResearchFailure
				if errors.As(fetchErr, &failure) && failure.RetryAfter > 0 {
					entry["retry_after_seconds"] = int(failure.RetryAfter/time.Second) + 1
				}
				attempts = append(attempts, entry)
				switch code {
				case "policy_denied", "policy_unavailable", "executor_unavailable", "cancelled":
					return actool.Errorf(code), nil
				}
				continue
			}
			completed++
			status := "results"
			if len(value.References) == 0 && value.Record == nil {
				status = "empty"
			}
			attempts = append(attempts, map[string]any{"source": source, "status": status, "cached": cached, "fetched_at": value.FetchedAt, "expires_at": value.ExpiresAt})
			groups = append(groups, value.References)
			if value.Record != nil {
				record = value.Record
			}
		}
		refs := mergeCVEReferences(groups...)
		total := len(refs)
		if len(refs) > args.Limit {
			refs = refs[:args.Limit]
		}
		outcome := "results"
		if completed == 0 {
			outcome = "failed"
		} else if len(refs) == 0 && record == nil {
			outcome = "empty"
		}
		if completed > 0 && completed < 3 {
			outcome += "_with_gaps"
		}
		result, err := jsonResult(map[string]any{"cve_id": args.CVE, "outcome": outcome, "vulnerability": record, "references": refs, "total_references": total, "truncated": total > len(refs), "sources": attempts, "untrusted": true, "confirmation": "references_only", "note": "Reference lists may be partial. Stars and indexed links do not prove correctness, safety or applicability. Source failure or an empty index is not negative evidence. No PoC code was downloaded or executed; confirmation still requires execution evidence and human review."})
		result.IsError = completed == 0
		return result, err
	})
}
