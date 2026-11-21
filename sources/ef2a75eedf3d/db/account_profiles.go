package db

import "database/sql"

func (d *DB) ActiveProfileForAccount(accountID int64) (*LLMProfile, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	var p LLMProfile
	err := scanProfile(d.QueryRow(`SELECT `+profileColsKey+` FROM llm_profiles WHERE account_id=$1 AND is_default LIMIT 1`, accountID), &p.APIKey, &p)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err == nil {
		err = d.openProfile(&p)
	}
	return &p, err
}

func (d *DB) SetActiveProfileForAccount(accountID, id int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owned int64
	if err = tx.QueryRow(`SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, accountID).Scan(&owned); err != nil {
		return err
	}
	if err = tx.QueryRow(`SELECT id FROM llm_profiles WHERE id=$1 AND account_id=$2`, id, accountID).Scan(&owned); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE llm_profiles SET is_default=false WHERE account_id=$1 AND is_default`, accountID); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE llm_profiles SET is_default=true WHERE id=$1 AND account_id=$2`, id, accountID); err != nil {
		return err
	}
	return tx.Commit()
}
