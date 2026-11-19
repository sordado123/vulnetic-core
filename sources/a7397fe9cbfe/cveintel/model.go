package cveintel

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type CVSS struct {
	Version  string   `json:"version"`
	Vector   string   `json:"vector,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Source   string   `json:"source"`
}

type Candidate struct {
	CVEID              string            `json:"cve_id"`
	Aliases            []string          `json:"aliases,omitempty"`
	Summary            string            `json:"summary"`
	Severity           string            `json:"severity"`
	CVSS               []CVSS            `json:"cvss,omitempty"`
	References         []string          `json:"references,omitempty"`
	Source             string            `json:"source"`
	Sources            []string          `json:"sources,omitempty"`
	MatchBasis         string            `json:"match_basis"`
	Applicability      string            `json:"applicability"`
	Affected           []json.RawMessage `json:"affected,omitempty"`
	Published          string            `json:"published,omitempty"`
	Modified           string            `json:"modified,omitempty"`
	FetchedAt          time.Time         `json:"fetched_at"`
	Stale              bool              `json:"stale"`
	EPSSScore          float64           `json:"epss_score,omitempty"`
	EPSSPercentile     float64           `json:"epss_percentile,omitempty"`
	EPSSKnown          bool              `json:"epss_known"`
	EPSSDate           string            `json:"epss_date,omitempty"`
	KEVListed          bool              `json:"kev_listed,omitempty"`
	KEVKnown           bool              `json:"kev_known"`
	KEVKnownRansomware bool              `json:"kev_known_ransomware,omitempty"`
}

type PackageQuery struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
}

func (q PackageQuery) Validate() error {
	if len(q.Name)+len(q.Ecosystem)+len(q.PURL)+len(q.Version)+len(q.Commit) > 4096 {
		return fmt.Errorf("package query exceeds limit")
	}
	if q.PURL != "" {
		if !strings.HasPrefix(q.PURL, "pkg:") || q.Name != "" || q.Ecosystem != "" {
			return fmt.Errorf("use purl or package name and ecosystem")
		}
		if q.Version != "" && strings.Contains(q.PURL, "@") {
			return fmt.Errorf("version must appear once")
		}
	} else if q.Name == "" || q.Ecosystem == "" {
		return fmt.Errorf("package name and explicit ecosystem are required")
	}
	if q.Commit != "" && (q.Version != "" || strings.Contains(q.PURL, "@")) {
		return fmt.Errorf("commit and version cannot be combined")
	}
	if q.Commit == "" && q.Version == "" && !strings.Contains(q.PURL, "@") {
		return fmt.Errorf("version or commit is required")
	}
	return nil
}
func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
func MergeCandidates(in []Candidate) []Candidate {
	// Resolve all alias links first, including a later record bridging two groups.
	parents := make([]int, len(in))
	for i := range parents {
		parents[i] = i
	}
	var root func(int) int
	root = func(i int) int {
		if parents[i] != i {
			parents[i] = root(parents[i])
		}
		return parents[i]
	}
	aliases := map[string]int{}
	for i, c := range in {
		if c.CVEID == "" {
			continue
		}
		for _, id := range append(append([]string(nil), c.Aliases...), c.CVEID) {
			if id == "" {
				continue
			}
			key := strings.ToUpper(id)
			if previous, ok := aliases[key]; ok {
				parents[root(i)] = root(previous)
			}
			aliases[key] = i
		}
	}
	out := []Candidate{}
	index := map[int]int{}
	for i, c := range in {
		if c.CVEID == "" {
			continue
		}
		c.Aliases = unique(append(c.Aliases, c.CVEID))
		c.Sources = unique(append(c.Sources, c.Source))
		c.References = unique(c.References)
		group := root(i)
		if at, ok := index[group]; ok {
			old := out[at]
			old.Aliases = unique(append(old.Aliases, c.Aliases...))
			old.Sources = unique(append(old.Sources, c.Sources...))
			old.References = unique(append(old.References, c.References...))
			old.CVSS = append(old.CVSS, c.CVSS...)
			old.Affected = append(old.Affected, c.Affected...)
			if old.Summary == "" {
				old.Summary = c.Summary
			}
			if old.Severity == "" {
				old.Severity = c.Severity
			}
			if old.Published == "" {
				old.Published = c.Published
			}
			if c.Modified > old.Modified {
				old.Modified = c.Modified
			}
			if c.FetchedAt.After(old.FetchedAt) {
				old.FetchedAt = c.FetchedAt
			}
			if c.EPSSKnown && (!old.EPSSKnown || c.EPSSDate >= old.EPSSDate) {
				old.EPSSKnown, old.EPSSScore, old.EPSSPercentile, old.EPSSDate = true, c.EPSSScore, c.EPSSPercentile, c.EPSSDate
			}
			old.KEVKnown = old.KEVKnown || c.KEVKnown
			old.KEVListed = old.KEVListed || c.KEVListed
			old.KEVKnownRansomware = old.KEVKnownRansomware || c.KEVKnownRansomware
			if strings.HasPrefix(strings.ToUpper(c.CVEID), "CVE-") {
				old.CVEID = c.CVEID
			}
			if old.MatchBasis == "keyword" && c.MatchBasis != "keyword" {
				old.MatchBasis = c.MatchBasis
				old.Applicability = c.Applicability
			}
			old.Stale = old.Stale || c.Stale
			out[at] = old
		} else {
			index[group] = len(out)
			out = append(out, c)
		}
	}
	return out
}
