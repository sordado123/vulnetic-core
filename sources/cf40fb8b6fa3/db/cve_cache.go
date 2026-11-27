package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// cveCacheMaxAge is how long a cached CVE candidate list is trusted before
// lookup_cve re-queries the external source. CVE data changes rarely enough
// hour-to-hour that a day is a reasonable default; callers may still force a
// refresh by ignoring a stale GetCVECache result.
const cveCacheMaxAge = 24 * time.Hour

// CVECacheEntry is one cached response from OSV or NVD for a (product,
// version) pair, as stored in cve_cache.
type CVECacheEntry struct {
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	Source    string          `json:"source"` // "osv" | "nvd"
	Response  json.RawMessage `json:"response"`
	FetchedAt time.Time       `json:"fetched_at"`
}

// Fresh reports whether this entry is still within cveCacheMaxAge.
func (e *CVECacheEntry) Fresh() bool {
	return e != nil && time.Since(e.FetchedAt) < cveCacheMaxAge
}

// GetCVECache returns the cached entry for (product, version, source), or nil
// (no error) when there is no row yet. Callers check Fresh() before trusting
// it — a stale row is still returned so a failed re-fetch can fall back to it.
func (d *DB) GetCVECache(product, version, source string) (*CVECacheEntry, error) {
	var e CVECacheEntry
	var raw []byte
	err := d.QueryRow(`
SELECT product, version, source, response, fetched_at
FROM cve_cache WHERE product = $1 AND version = $2 AND source = $3`,
		product, version, source,
	).Scan(&e.Product, &e.Version, &e.Source, &raw, &e.FetchedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Response = json.RawMessage(raw)
	return &e, nil
}

// UpsertCVECache writes/refreshes the cached response for (product, version,
// source), bumping fetched_at to now.
func (d *DB) UpsertCVECache(product, version, source string, response json.RawMessage) error {
	_, err := d.Exec(`
INSERT INTO cve_cache(product, version, source, response, fetched_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (product, version, source)
DO UPDATE SET response = EXCLUDED.response, fetched_at = EXCLUDED.fetched_at`,
		product, version, source, string(response))
	return err
}

// AssetCVECandidate is one display-only row mirrored for the UI (Peça 5) —
// never an exploration-graph node, never treated as a fact or finding.
type AssetCVECandidate struct {
	Details   json.RawMessage `json:"details"`
	AssetID   int64           `json:"asset_id"`
	CVEID     string          `json:"cve_id"`
	Severity  string          `json:"severity"`
	EPSSScore float64         `json:"epss_score"`
	KEVListed bool            `json:"kev_listed"`
	Source    string          `json:"source"`
	FetchedAt time.Time       `json:"fetched_at"`
}

// UpsertAssetCVECandidates mirrors a lookup_cve result against every asset id
// the call named, for the "CVE Candidates" UI tab. Best-effort: callers log
// and continue on error rather than fail the (already-returned) tool result.
func (d *DB) UpsertAssetCVECandidates(assetIDs []int64, candidates []AssetCVECandidate) error {
	if len(assetIDs) == 0 || len(candidates) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, assetID := range assetIDs {
		if d.hasAccount {
			var owned bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1 AND account_id=$2)`, assetID, d.accountID).Scan(&owned); err != nil {
				return err
			}
			if !owned {
				return fmt.Errorf("asset not found")
			}
		}
		for _, c := range candidates {
			if _, err := tx.Exec(`
INSERT INTO asset_cve_candidates(asset_id, cve_id, severity, epss_score, kev_listed, source, details, fetched_at)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::jsonb,'{}'::jsonb), now())
ON CONFLICT (asset_id, cve_id)
DO UPDATE SET severity = EXCLUDED.severity, epss_score = EXCLUDED.epss_score,
              kev_listed = EXCLUDED.kev_listed, source = EXCLUDED.source, details=EXCLUDED.details,
              fetched_at = EXCLUDED.fetched_at`,
				assetID, c.CVEID, c.Severity, c.EPSSScore, c.KEVListed, c.Source, nullableJSON(c.Details),
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// AssetCVECandidates returns the cached CVE candidates mirrored for one
// asset, most relevant (KEV, then EPSS) first — read by the Peça 5 API route.
func (d *DB) AssetCVECandidates(assetID int64) ([]AssetCVECandidate, error) {
	rows, err := d.Query(`
SELECT asset_id, cve_id, COALESCE(severity,''), COALESCE(epss_score,0), kev_listed, source, fetched_at, details
FROM asset_cve_candidates
WHERE asset_id = $1 AND EXISTS(SELECT 1 FROM assets WHERE id=asset_id AND `+d.tenantSQL("")+`)
ORDER BY kev_listed DESC, epss_score DESC, cve_id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetCVECandidate{}
	for rows.Next() {
		var c AssetCVECandidate
		if err := rows.Scan(&c.AssetID, &c.CVEID, &c.Severity, &c.EPSSScore, &c.KEVListed, &c.Source, &c.FetchedAt, &c.Details); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// KEVEntry is one row of the mirrored CISA Known Exploited Vulnerabilities
// catalog (kev_catalog).
type KEVEntry struct {
	CVEID           string     `json:"cve_id"`
	DateAdded       *time.Time `json:"date_added,omitempty"`
	DueDate         *time.Time `json:"due_date,omitempty"`
	KnownRansomware bool       `json:"known_ransomware"`
	FetchedAt       time.Time  `json:"fetched_at"`
}

// KEVLookup returns the kev_catalog row for a CVE id, or nil when it is not
// listed (not an error — "not in KEV" is the common case).
func (d *DB) KEVLookup(cveID string) (*KEVEntry, error) {
	var e KEVEntry
	var dateAdded, dueDate sql.NullTime
	err := d.QueryRow(`
SELECT cve_id, date_added, due_date, known_ransomware, fetched_at
FROM kev_catalog WHERE cve_id = $1`, cveID,
	).Scan(&e.CVEID, &dateAdded, &dueDate, &e.KnownRansomware, &e.FetchedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if dateAdded.Valid {
		e.DateAdded = &dateAdded.Time
	}
	if dueDate.Valid {
		e.DueDate = &dueDate.Time
	}
	return &e, nil
}

// KEVCatalogAge returns the newest fetched_at in kev_catalog, or the zero
// time when the catalog has never been refreshed — the caller's signal to
// run RefreshKEVCatalog before trusting KEVLookup results as complete.
func (d *DB) KEVCatalogAge() (time.Time, error) {
	var t sql.NullTime
	if err := d.QueryRow(`SELECT MAX(fetched_at) FROM kev_catalog`).Scan(&t); err != nil {
		return time.Time{}, err
	}
	if !t.Valid {
		return time.Time{}, nil
	}
	return t.Time, nil
}

// ReplaceKEVCatalog swaps the whole kev_catalog contents atomically — the
// feed is small (a few thousand rows) and has no stable per-row versioning,
// so a full replace is simpler and safer than diffing.
func (d *DB) ReplaceKEVCatalog(entries []KEVEntry) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM kev_catalog`); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := tx.Exec(`
INSERT INTO kev_catalog(cve_id, date_added, due_date, known_ransomware, fetched_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (cve_id) DO UPDATE SET date_added = EXCLUDED.date_added,
    due_date = EXCLUDED.due_date, known_ransomware = EXCLUDED.known_ransomware,
    fetched_at = EXCLUDED.fetched_at`,
			e.CVEID, e.DateAdded, e.DueDate, e.KnownRansomware,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullableJSON(data json.RawMessage) any {
	if len(data) == 0 {
		return nil
	}
	return string(data)
}
