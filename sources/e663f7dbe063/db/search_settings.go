package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

const accountSearchSetting = "research.config.v1"

var ErrSearchSettings = errors.New("invalid research settings")

type AccountSearchConfig struct {
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	Backend   string `json:"backend"`
	TavilyKey string `json:"tavily_key"`
	ExaKey    string `json:"exa_key"`
	LinkupKey string `json:"linkup_key"`
}

type AccountSearchPatch struct {
	Enabled   *bool   `json:"enabled"`
	Backend   *string `json:"backend"`
	TavilyKey *string `json:"tavily_key"`
	ExaKey    *string `json:"exa_key"`
	LinkupKey *string `json:"linkup_key"`
}

func (d *DB) SearchConfig() (AccountSearchConfig, error) {
	c := AccountSearchConfig{Version: 1, Enabled: true, Backend: "mwmbl"}
	if !d.hasAccount || d.accountID <= 0 {
		return c, errors.New("authenticated account required")
	}
	value, found, err := d.GetSetting(accountSearchSetting)
	if err != nil || !found {
		return c, err
	}
	raw, err := d.openJSON(d.accountID, json.RawMessage(value))
	if err != nil {
		return c, err
	}
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 || !validSearchBackend(c.Backend) {
		return c, errors.New("research policy unavailable")
	}
	return c, nil
}

func validSearchBackend(value string) bool {
	switch value {
	case "mwmbl", "ddgs", "tavily", "exa", "linkup":
		return true
	}
	return false
}

// Lock one account setting so simultaneous saves preserve omitted credentials.
func (d *DB) SaveSearchConfig(ctx context.Context, patch AccountSearchPatch) (AccountSearchConfig, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return AccountSearchConfig{}, errors.New("authenticated account required")
	}
	tx, nested := d.Querier.(*sql.Tx)
	if !nested {
		var err error
		tx, err = d.BeginTx(ctx, nil)
		if err != nil {
			return AccountSearchConfig{}, err
		}
		defer tx.Rollback()
	}
	scoped := *d
	scoped.Querier = tx
	if _, err := tx.ExecContext(ctx, `INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,'{}') ON CONFLICT DO NOTHING`, d.accountID, accountSearchSetting); err != nil {
		return AccountSearchConfig{}, err
	}
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM account_settings WHERE account_id=$1 AND key=$2 FOR UPDATE`, d.accountID, accountSearchSetting).Scan(&locked); err != nil {
		return AccountSearchConfig{}, err
	}
	c, err := scoped.SearchConfig()
	if err != nil {
		return c, err
	}
	if patch.Enabled != nil {
		c.Enabled = *patch.Enabled
	}
	if patch.Backend != nil {
		c.Backend = strings.ToLower(strings.TrimSpace(*patch.Backend))
	}
	if !validSearchBackend(c.Backend) {
		return c, ErrSearchSettings
	}
	for _, key := range []struct {
		input  *string
		output *string
	}{{patch.TavilyKey, &c.TavilyKey}, {patch.ExaKey, &c.ExaKey}, {patch.LinkupKey, &c.LinkupKey}} {
		if key.input == nil {
			continue
		}
		value := strings.TrimSpace(*key.input)
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") || value == SecretMask {
			return c, ErrSearchSettings
		}
		*key.output = value
	}
	if c.Enabled && ((c.Backend == "tavily" && c.TavilyKey == "") || (c.Backend == "exa" && c.ExaKey == "") || (c.Backend == "linkup" && c.LinkupKey == "")) {
		return c, ErrSearchSettings
	}
	if !scoped.encryptSecrets && (c.TavilyKey != "" || c.ExaKey != "" || c.LinkupKey != "") {
		return c, errors.New("credential vault unavailable")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	sealed, err := scoped.sealJSON(d.accountID, raw)
	if err != nil {
		return c, err
	}
	if err = scoped.SetSetting(accountSearchSetting, string(sealed)); err != nil {
		return c, err
	}
	if !nested {
		err = tx.Commit()
	}
	return c, err
}
