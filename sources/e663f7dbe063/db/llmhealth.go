package db

import (
	"context"
	"database/sql"
	"time"
)

// LLM failover health: one row per profile tracking its circuit-breaker state.
// The authoritative copy lives in memory (llmpool.Registry); this table only
// survives a restart so a cooling-off window isn't silently reset by one.

// LLMHealth is one profile's circuit-breaker state.
type LLMHealth struct {
	ProfileID int64      `json:"profile_id"`
	Fails     int        `json:"fails"`      // consecutive failures; cleared on success
	Trips     int        `json:"trips"`      // total trips, drives the backoff ladder
	OpenUntil *time.Time `json:"open_until"` // nil/past = closed (healthy)
	LastError string     `json:"last_error"`
	LastAt    time.Time  `json:"last_at"`
}

// LoadLLMHealth returns the profiles still in an UNEXPIRED cooling-off window.
// Expired rows are deliberately skipped: after a restart a profile that has
// finished cooling should be treated as healthy again and re-probed on its next
// call, not resurrected as broken.
func (d *DB) LoadLLMHealth() ([]LLMHealth, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		ids, err := d.RuntimeAccountIDs()
		if err != nil {
			return nil, err
		}
		var all []LLMHealth
		for _, id := range ids {
			rows, err := d.ForAccount(id).LoadLLMHealth()
			if err != nil {
				return nil, err
			}
			all = append(all, rows...)
		}
		return all, nil
	}
	rows, err := d.Query(`SELECT profile_id,fails,trips,open_until,COALESCE(last_error,''),last_at
FROM llm_profile_health h WHERE open_until IS NOT NULL AND open_until > now() AND EXISTS(SELECT 1 FROM llm_profiles p WHERE p.id=h.profile_id AND ` + d.tenantSQL("p.") + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMHealth
	for rows.Next() {
		var h LLMHealth
		if err := rows.Scan(&h.ProfileID, &h.Fails, &h.Trips, &h.OpenUntil, &h.LastError, &h.LastAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SaveLLMHealth upserts one profile's circuit-breaker state.
func (d *DB) SaveLLMHealth(h LLMHealth) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("profile", h.ProfileID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := d.ExecContext(ctx, `
INSERT INTO llm_profile_health(profile_id,fails,trips,open_until,last_error,last_at)
SELECT $1,$2,$3,$4,$5,now() FROM llm_profiles p WHERE p.id=$1 AND `+d.tenantSQL("p.")+`
ON CONFLICT (profile_id) DO UPDATE SET
  fails=EXCLUDED.fails, trips=EXCLUDED.trips, open_until=EXCLUDED.open_until,
  last_error=EXCLUDED.last_error, last_at=now()`,
		h.ProfileID, h.Fails, h.Trips, h.OpenUntil, h.LastError)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

// ClearLLMHealth drops one profile's state (manual "recover now" from the UI).
func (d *DB) ClearLLMHealth(profileID int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("profile", profileID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.ExecContext(ctx, `DELETE FROM llm_profile_health h WHERE profile_id=$1 AND EXISTS(SELECT 1 FROM llm_profiles p WHERE p.id=h.profile_id AND `+d.tenantSQL("p.")+`)`, profileID)
	return err
}
