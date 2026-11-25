package server

import (
	"encoding/json"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
)

func ensureAgentToolProfiles(pg *db.DB) error {
	if !config.SaaSMode() {
		return nil
	}
	if value, ok, err := pg.GetSetting(db.AgentToolProfilesVersion); err != nil {
		return err
	} else if ok && value == "true" {
		return nil
	}
	// Bash/Sleep used to bypass the catalog; seed them so their bindings are visible and editable.
	for _, seed := range agent.BuiltinToolSeeds() {
		schema, err := json.Marshal(seed.Schema)
		if err != nil {
			return err
		}
		bindings, err := json.Marshal(seed.Agents)
		if err != nil {
			return err
		}
		if err := pg.SeedTool(seed.Key, seed.Desc, schema, bindings); err != nil {
			return err
		}
	}
	return pg.ApplyAgentToolProfiles(agent.DefaultToolProfiles())
}
