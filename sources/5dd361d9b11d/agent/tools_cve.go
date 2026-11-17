package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/cveintel"
	"github.com/sordado123/vulnetic/db"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

// kevRefreshMaxAge mirrors the cache-age-checked-in-Go pattern used
// throughout db/ (see cve_cache.go) for the CISA KEV mirror.
const kevRefreshMaxAge = 24 * time.Hour

// SetCVE wires the CVE intelligence client onto the Worker, for every run it
// executes (worker/auto/pentest/retester share this one executor — see
// execute()'s `name` param). Mirrors SetFindingRecorder's shape
// (agent/finding_recorder.go): set once per Worker instance, copied onto the
// per-run ToolSet inside execute().
func (w *Worker) SetCVE(c *cveintel.Client, store *db.DB) {
	w.cve = c
	w.cveDB = store
}

// lookupCVE is the lookup_cve tool: given a fingerprinted product/version (or
// a raw technologies string), query OSV.dev (and NVD as a fallback) for CVE
// candidates, annotate them with EPSS/KEV priority signals, and return them
// as read-only text. It NEVER writes a fact/finding/hint itself — see the
// tool description below and the golden rule in agent/promptcatalog.go and
// agent/worker.go: version/CVE matching is never sufficient evidence for
// report_finding. Use readTool (no t.ts dependency) so this works for any
// agent, including ones that are not inside a task's exploration graph.
func (t *ToolSet) lookupCVE() actool.CoreTool {
	return readTool("lookup_cve",
		"Query OSV.dev (and NVD as a fallback) for CVE candidates matching a fingerprinted "+
			"product/version. Returns CANDIDATES ONLY from version/package matching — this is "+
			"NEVER sufficient evidence for report_finding (see the golden rule in your system "+
			"prompt: version/fingerprint matching a CVE is explicitly forbidden as confirmation). "+
			"If a candidate is worth tracking, use record_fact citing this source as the evidence "+
			"(mark confidence=inferred). To actually confirm one, invoke the cve-verify skill "+
			"(selects a reviewed verifier and validates its prerequisites before execution) or use a reviewed manual procedure and "+
			"get real triggered evidence. Results are sorted by priority: CISA KEV-listed first, "+
			"then by EPSS exploitation-probability score, severity as the final tie-break — when "+
			"several candidates come back, the top of the list is the one worth trying first; you "+
			"do not need to verify every candidate, stop once you have real evidence or exhaust budget.",
		obj(map[string]any{
			"ecosystem": str("Explicit package ecosystem, e.g. npm, PyPI or Debian:12; never infer it from a server banner"),
			"purl":      str("Optional explicit package URL, including its version"),
			"commit":    str("Optional package commit instead of version"),
			"cpe":       str("Optional explicit CPE 2.3 name; configuration still requires verification"),
			"product":   str("software product name, e.g. 'nginx' (used with version; takes priority over technologies)"),
			"version":   str("version string, e.g. '1.25.3' (used with product)"),
			"technologies": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "optional: raw fingerprint strings (e.g. from an asset's technologies field) instead of product+version; each is best-effort parsed and reported honestly as unparsed when it fails, never silently treated as 'no CVEs found'",
			},
			"asset_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "optional: asset ids this fingerprint came from. When set, candidates are also mirrored to those assets for the UI's CVE Candidates view — this is a display-only mirror, never a fact/finding/hint, so passing it does not change the golden-rule obligations above",
			},
		}),
		t.runLookupCVE,
	)
}

type lookupCVEInput struct {
	Ecosystem    string   `json:"ecosystem"`
	PURL         string   `json:"purl"`
	Commit       string   `json:"commit"`
	CPE          string   `json:"cpe"`
	Product      string   `json:"product"`
	Version      string   `json:"version"`
	Technologies []string `json:"technologies"`
	AssetIDs     []int64  `json:"asset_ids"`
}

// cvePair is one (product, version) query target, after normalizing the
// input (direct product+version, or best-effort parsed technologies).
type cvePair struct {
	product   string
	version   string
	rawSource string // the original technologies string, for "could not parse" reporting
}

func (t *ToolSet) runLookupCVE(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	if t.cve == nil || t.cveDB == nil {
		return actool.Errorf("CVE intelligence unavailable"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var input lookupCVEInput
	if json.Unmarshal(in, &input) != nil {
		return actool.Errorf("Invalid CVE lookup input"), nil
	}
	if len(input.AssetIDs) > 20 || len(input.Technologies) > 8 {
		return actool.Errorf("Lookup limit exceeded"), nil
	}
	accountID := RunInfoFrom(ctx).AccountID
	if len(input.AssetIDs) > 0 {
		if accountID <= 0 {
			return actool.Errorf("Authenticated account is required"), nil
		}
		assets, err := t.cveDB.ForAccount(accountID).Assets().GetByIDs(input.AssetIDs)
		if err != nil || len(assets) != len(input.AssetIDs) {
			return actool.Errorf("Asset not found"), nil
		}
	}
	var pairs []cvePair
	unparsed := []string{}
	notes := []string{}
	sourceStates := map[string]string{}
	if input.Product != "" && input.Version != "" {
		pairs = append(pairs, cvePair{product: strings.TrimSpace(input.Product), version: strings.TrimSpace(input.Version)})
	}
	for _, raw := range input.Technologies {
		p, v, ok := cveintel.NormalizeProductVersion(raw)
		if !ok {
			unparsed = append(unparsed, raw)
		} else {
			pairs = append(pairs, cvePair{product: p, version: v})
		}
	}
	var all []cveintel.Candidate
	lookup := func(source string, query any, fetch func() ([]cveintel.Candidate, error)) {
		data, _ := json.Marshal(query)
		key := fmt.Sprintf("v2:%x", sha256.Sum256(data))
		candidates, stale, err := t.cachedOrFetch(ctx, key, "v2", source, fetch)
		if err != nil {
			notes = append(notes, source+": "+err.Error())
			sourceStates[source] = "unavailable"
			return
		}
		state := "fresh"
		if stale {
			state = "stale"
			notes = append(notes, source+": using stale data after refresh failed")
		}
		sourceStates[source] = state
		all = append(all, candidates...)
	}
	if input.Ecosystem != "" || input.PURL != "" {
		q := cveintel.PackageQuery{Name: input.Product, Ecosystem: input.Ecosystem, PURL: input.PURL, Version: input.Version, Commit: input.Commit}
		if input.PURL != "" {
			q.Name = ""
		}
		if err := q.Validate(); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		lookup("osv", q, func() ([]cveintel.Candidate, error) { return t.cve.QueryPackage(ctx, q) })
	} else if len(pairs) > 0 {
		notes = append(notes, "OSV not queried: an explicit package ecosystem or purl is required; banner identity does not identify a distribution")
	}
	if input.CPE != "" {
		lookup("nvd", map[string]string{"cpe": input.CPE}, func() ([]cveintel.Candidate, error) { return t.cve.QueryCPE(ctx, input.CPE) })
	} else if input.Ecosystem == "" && input.PURL == "" {
		for _, p := range pairs {
			p := p
			lookup("nvd", p.product+"\n"+p.version, func() ([]cveintel.Candidate, error) { return t.cve.QueryNVD(ctx, p.product, p.version) })
		}
	}
	all = cveintel.MergeCandidates(all)
	t.annotateEPSSAndKEV(ctx, all)
	sortCandidatesByPriority(all)
	total := len(all)
	if len(all) > 20 {
		all = all[:20]
		notes = append(notes, "Display limited to 20 candidates; this is not complete coverage")
	}
	if len(input.AssetIDs) > 0 {
		rows := make([]db.AssetCVECandidate, 0, len(all))
		for _, c := range all {
			details, _ := json.Marshal(c)
			rows = append(rows, db.AssetCVECandidate{CVEID: c.CVEID, Severity: c.Severity, EPSSScore: c.EPSSScore, KEVListed: c.KEVListed, Source: c.Source, Details: details})
		}
		if err := t.cveDB.ForAccount(accountID).UpsertAssetCVECandidates(input.AssetIDs, rows); err != nil {
			notes = append(notes, "Candidate display could not be persisted")
		}
	}
	return jsonResult(map[string]any{"candidates": all, "total_candidates": total, "sources": sourceStates, "notes": notes, "unparsed_technologies": unparsed, "confirmation": "candidates_only", "note": "No candidate confirms a vulnerability. Unavailable sources and unparsed fingerprints do not indicate a clean target."})
}

func (t *ToolSet) cachedOrFetch(ctx context.Context, product, version, source string, fetch func() ([]cveintel.Candidate, error)) ([]cveintel.Candidate, bool, error) {
	entry, _ := t.cveDB.GetCVECache(product, version, source)
	var cached []cveintel.Candidate
	valid := entry != nil && json.Unmarshal(entry.Response, &cached) == nil
	if valid && entry.Fresh() {
		return cached, false, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	candidates, err := fetch()
	if err != nil {
		if valid {
			for i := range cached {
				cached[i].Stale = true
				cached[i].FetchedAt = entry.FetchedAt
			}
			return cached, true, nil
		}
		return nil, false, err
	}
	raw, err := json.Marshal(candidates)
	if err == nil {
		_ = t.cveDB.UpsertCVECache(product, version, source, raw)
	}
	return candidates, false, nil
}

// annotateEPSSAndKEV fills EPSSScore/EPSSPercentile/KEVListed/
// KEVKnownRansomware in place (Peça 4). Best-effort throughout: a failed
// EPSS/KEV lookup leaves those fields at their zero value rather than
// failing the whole lookup_cve call — priority sorting degrades gracefully.
func (t *ToolSet) annotateEPSSAndKEV(ctx context.Context, cands []cveintel.Candidate) {
	ids := make([]string, 0, len(cands))
	for _, c := range cands {
		if c.CVEID != "" {
			ids = append(ids, c.CVEID)
		}
	}
	if len(ids) == 0 {
		return
	}
	if scores, err := t.cve.QueryEPSS(ctx, ids); err == nil {
		for i := range cands {
			if s, ok := scores[strings.ToUpper(cands[i].CVEID)]; ok {
				cands[i].EPSSKnown = true
				cands[i].EPSSDate = s.Date
				cands[i].EPSSScore = s.Score
				cands[i].EPSSPercentile = s.Percentile
			}
		}
	}

	if age, err := t.cveDB.KEVCatalogAge(); err == nil && kevStale(age) {
		if entries, err := t.cve.RefreshKEVCatalog(ctx); err == nil {
			dbEntries := make([]db.KEVEntry, 0, len(entries))
			for _, e := range entries {
				dbEntries = append(dbEntries, db.KEVEntry{
					CVEID: e.CVEID, DateAdded: e.DateAdded, DueDate: e.DueDate,
					KnownRansomware: e.KnownRansomware,
				})
			}
			_ = t.cveDB.ReplaceKEVCatalog(dbEntries)
		}
	}
	age, ageErr := t.cveDB.KEVCatalogAge()
	for i := range cands {
		cands[i].KEVKnown = ageErr == nil && !kevStale(age)
		if cands[i].CVEID == "" {
			continue
		}
		if kev, err := t.cveDB.KEVLookup(cands[i].CVEID); err == nil && kev != nil {
			cands[i].KEVListed = true
			cands[i].KEVKnownRansomware = kev.KnownRansomware
		}
	}
}

func kevStale(fetchedAt time.Time) bool {
	return fetchedAt.IsZero() || time.Since(fetchedAt) > kevRefreshMaxAge
}

// sortCandidatesByPriority orders KEV-listed first, then by EPSS score
// descending, severity string as the final (weak) tie-break — see Peça 4.
func sortCandidatesByPriority(cands []cveintel.Candidate) {
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].KEVListed != cands[j].KEVListed {
			return cands[i].KEVListed
		}
		if cands[i].EPSSScore != cands[j].EPSSScore {
			return cands[i].EPSSScore > cands[j].EPSSScore
		}
		ranks := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		a, b := ranks[strings.ToLower(cands[i].Severity)], ranks[strings.ToLower(cands[j].Severity)]
		if a != b {
			return a > b
		}
		return cands[i].CVEID < cands[j].CVEID
	})
}
