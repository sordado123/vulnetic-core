package db

import "database/sql"

// Settings is a tiny key-value store for global app config the UI toggles at
// runtime (e.g. traffic_capture). Missing keys fall back to caller defaults.

// GetSetting returns the stored value and ok=false when the key is unset.
func (d *DB) GetSetting(key string) (value string, ok bool, err error) {
	if d.hasAccount {
		err = d.QueryRow(`SELECT value FROM account_settings WHERE account_id=$1 AND key=$2`, d.accountID, key).Scan(&value)
	} else {
		err = d.QueryRow(`SELECT value FROM settings WHERE key=$1`, key).Scan(&value)
	}
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting upserts a setting value.
func (d *DB) SetSetting(key, value string) error {
	if d.hasAccount {
		_, err := d.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,$3) ON CONFLICT(account_id,key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()`, d.accountID, key, value)
		return err
	}
	_, err := d.Exec(`
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value)
	return err
}

// InsertSettingIfAbsent writes only when the key does not exist yet; an existing key is
// kept as-is and inserted=false is returned.
// For keys like auth.password_hash that "may only be set on first run": the judgment rests
// on the database primary-key constraint. A caller doing GetSetting-then-write is just a
// fast-fail path — on a read error or a concurrent race, the existing value will not be
// silently overwritten by ON CONFLICT DO UPDATE.
func (d *DB) InsertSettingIfAbsent(key, value string) (inserted bool, err error) {
	if d.hasAccount {
		result, err := d.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,$3) ON CONFLICT(account_id,key) DO NOTHING`, d.accountID, key, value)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		return n > 0, err
	}
	res, err := d.Exec(`
INSERT INTO settings(key, value) VALUES ($1, $2)
ON CONFLICT (key) DO NOTHING`, key, value)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetBool returns the boolean setting, or def when unset/unparseable.
func (d *DB) GetBool(key string, def bool) bool {
	v, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	return v == "true" || v == "1"
}

// SetBool stores a boolean setting as "true"/"false".
func (d *DB) SetBool(key string, val bool) error {
	if val {
		return d.SetSetting(key, "true")
	}
	return d.SetSetting(key, "false")
}
