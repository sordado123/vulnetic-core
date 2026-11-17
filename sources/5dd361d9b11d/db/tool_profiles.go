package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

const AgentToolProfilesVersion = "agent_tool_profiles_v1"

// ApplyAgentToolProfiles updates only system-tool bindings for the supplied roles.
// The marker and bindings commit together; customer tools and other agents survive.
func (d *DB) ApplyAgentToolProfiles(profiles map[string][]string) error {
	if !d.hasAccount || d.accountID <= 0 {
		return fmt.Errorf("authenticated account required for agent tool profiles")
	}
	tx, nested := d.Querier.(*sql.Tx)
	if !nested {
		var err error
		tx, err = d.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	result, err := tx.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,'true') ON CONFLICT(account_id,key) DO NOTHING`, d.accountID, AgentToolProfilesVersion)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if !nested {
			return tx.Commit()
		}
		return nil
	}
	for role, keys := range profiles {
		raw, err := json.Marshal(keys)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE tools SET agents=(agents - $2::text) || CASE WHEN key IN (SELECT jsonb_array_elements_text($3::jsonb)) THEN jsonb_build_array($2::text) ELSE '[]'::jsonb END, updated_at=now() WHERE account_id=$1 AND system`, d.accountID, role, raw)
		if err != nil {
			return err
		}
	}
	if !nested {
		return tx.Commit()
	}
	return nil
}
