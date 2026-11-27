package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidFindingPatch = errors.New("invalid finding patch")
var ErrFindingNotVerified = errors.New("review execution evidence before confirming this candidate")

type FindingPatch struct {
	Status    *string `json:"status"`
	Severity  *string `json:"severity"`
	Name      *string `json:"name"`
	VulnClass *string `json:"vulnclass"`
}

func (d *DB) PatchFinding(ctx context.Context, id int64, p FindingPatch, requireVerified bool) (*DBFinding, error) {
	if p.Status == nil && p.Severity == nil && p.Name == nil && p.VulnClass == nil {
		return nil, ErrInvalidFindingPatch
	}
	if p.Status != nil && !ValidFindingStatus(*p.Status) {
		return nil, fmt.Errorf("%w: bad status", ErrInvalidFindingPatch)
	}
	if p.Severity != nil && !ValidSeverity(*p.Severity) {
		return nil, fmt.Errorf("%w: bad severity", ErrInvalidFindingPatch)
	}
	tx, existing := d.Querier.(*sql.Tx)
	if !existing {
		var err error
		tx, err = d.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return nil, err
	}
	var owned int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE id=$1 AND `+d.tenantSQL("")+` FOR UPDATE`, id).Scan(&owned); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	scoped := *d
	scoped.Querier = tx
	current, err := scoped.GetFinding(id)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, ErrFindingNotFound
	}
	if p.Status != nil {
		if requireVerified && *p.Status == FindingConfirmed && current.VerificationState != "verified" {
			return nil, ErrFindingNotVerified
		}
		if _, _, _, _, err = SetFindingStatusTx(ctx, tx, id, *p.Status); err != nil {
			return nil, err
		}
	}
	for _, field := range []struct {
		value       *string
		column, key string
	}{{p.Severity, "severity", "severity"}, {p.Name, "name", "name"}, {p.VulnClass, "vulnclass", "vulnclass"}} {
		if field.value != nil {
			if _, err = scoped.setFindingCol(id, field.column, field.key, strings.TrimSpace(*field.value)); err != nil {
				return nil, err
			}
		}
	}
	result, err := scoped.GetFinding(id)
	if err != nil {
		return nil, err
	}
	if !existing {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
	}
	return result, nil
}
