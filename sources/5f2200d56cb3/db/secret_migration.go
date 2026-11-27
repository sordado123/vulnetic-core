package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MigrateSecrets changes only credential fields, atomically. Versioned ciphertext is authenticated on every restart.
func (d *DB) MigrateSecrets() error {
	if !d.encryptSecrets {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741004)`); err != nil {
		return err
	}
	for _, spec := range []struct {
		table, column, owner string
		json                 bool
	}{
		{"llm_profiles", "api_key", "account_id", false}, {"llm_profiles", "base_url", "account_id", false}, {"llm_profiles", "proxy", "account_id", false},
		{"mcp_servers", "command", "account_id", false}, {"mcp_servers", "url", "account_id", false}, {"mcp_servers", "args", "account_id", true}, {"mcp_servers", "env", "account_id", true},
		{"notification_channels", "config", "account_id", true},
		{"task_credentials", "password", "(SELECT account_id FROM tasks WHERE tasks.id=task_id)", false},
	} {
		// Identifiers are exclusively the code-owned list above.
		query := fmt.Sprintf(`SELECT id,%s,COALESCE(%s::text,'') FROM %s FOR UPDATE`, spec.owner, spec.column, spec.table)
		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		type row struct {
			id, account int64
			value       string
		}
		var values []row
		for rows.Next() {
			var value row
			if err = rows.Scan(&value.id, &value.account, &value.value); err != nil {
				rows.Close()
				return err
			}
			values = append(values, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, value := range values {
			if value.value == "" {
				continue
			}
			var sealed string
			if spec.json {
				plain, err := d.openJSON(value.account, json.RawMessage(value.value))
				if err != nil {
					return err
				}
				if strings.Contains(value.value, `"__vulnetic_vault"`) {
					continue
				}
				wrapped, err := d.sealJSON(value.account, plain)
				if err != nil {
					return err
				}
				sealed = string(wrapped)
			} else {
				plain, err := d.openSecret(value.account, value.value)
				if err != nil {
					return err
				}
				if strings.HasPrefix(value.value, secretPrefix) {
					continue
				}
				sealed, err = d.sealSecret(value.account, plain)
				if err != nil {
					return err
				}
			}
			cast := ""
			if spec.json {
				cast = "::jsonb"
			}
			if _, err = tx.Exec(fmt.Sprintf(`UPDATE %s SET %s=$2%s WHERE id=$1`, spec.table, spec.column, cast), value.id, sealed); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(`INSERT INTO beta_migrations(version) VALUES(6) ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	return tx.Commit()
}
