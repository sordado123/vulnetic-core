package db

import (
	"database/sql"
	"strconv"
)

// ForAccount retains the existing transaction/pool and makes catalog ownership explicit.
func (d *DB) ForAccount(id int64) *DB {
	if d.scopeErr != nil {
		copy := *d
		return &copy
	}
	if d.runtime != nil {
		if _, inTransaction := d.Querier.(*sql.Tx); !inTransaction {
			return d.runtimeAccount(id)
		}
	}
	copy := *d
	copy.accountID = id
	copy.hasAccount = true
	return &copy
}

func (d *DB) catalogAccount() int64 {
	if d.hasAccount {
		return d.accountID
	}
	return LegacyAccountID // trusted startup seeding and legacy local callers only
}
func (d *DB) catalogSQL() string { return strconv.FormatInt(d.catalogAccount(), 10) }

// Unscoped handles are reserved for trusted jobs and migrations.
func (d *DB) tenantSQL(alias string) string {
	if !d.hasAccount {
		return "TRUE"
	}
	return alias + "account_id=" + d.catalogSQL()
}

func (d *DB) requireAgent(id int64) error {
	var owned bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1 AND account_id=$2)`, id, d.catalogAccount()).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return sql.ErrNoRows
	}
	return nil
}
