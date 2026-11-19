package cveintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// KEVEntry is one row of the CISA Known Exploited Vulnerabilities catalog.
// Deliberately independent of db.KEVEntry — this package does not import db
// (see package doc); callers convert and persist via db.ReplaceKEVCatalog.
type KEVEntry struct {
	CVEID           string
	DateAdded       *time.Time
	DueDate         *time.Time
	KnownRansomware bool
}

const kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevVuln struct {
	CveID                      string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type kevFeed struct {
	Vulnerabilities []kevVuln `json:"vulnerabilities"`
}

// RefreshKEVCatalog downloads the whole CISA KEV feed and parses it. It is a
// small flat JSON file (a few thousand rows) with no stable per-row
// versioning, so callers that want freshness just re-fetch the whole thing
// (gated by age in the caller, see db.KEVCatalogAge) rather than diff it.
func (c *Client) RefreshKEVCatalog(ctx context.Context) ([]KEVEntry, error) {
	raw, err := c.doRequest(ctx, http.MethodGet, kevCatalogURL, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cisa kev: %w", err)
	}
	var feed kevFeed
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, fmt.Errorf("cisa kev: malformed response: %w", err)
	}
	out := make([]KEVEntry, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		e := KEVEntry{
			CVEID:           v.CveID,
			KnownRansomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		}
		if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
			e.DateAdded = &t
		}
		if t, err := time.Parse("2006-01-02", v.DueDate); err == nil {
			e.DueDate = &t
		}
		out = append(out, e)
	}
	return out, nil
}
