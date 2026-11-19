package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/db"
)

func TestResearchSettingsNeverReturnKeys(t *testing.T) {
	c := db.AccountSearchConfig{Enabled: true, Backend: "exa", TavilyKey: "tavily-fixture-secret", ExaKey: "exa-fixture-secret", LinkupKey: "linkup-fixture-secret"}
	raw, err := json.Marshal(searchSettingsResponse(c))
	if err != nil || strings.Contains(string(raw), "fixture-secret") {
		t.Fatal("API exposed credentials")
	}
	var response map[string]any
	if json.Unmarshal(raw, &response) != nil || response["exa_key_set"] != true || response["backend"] != "exa" {
		t.Fatal("missing safe settings indicators")
	}
}
