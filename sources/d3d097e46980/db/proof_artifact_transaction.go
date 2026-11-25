package db

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ProofArtifactTransaction serializes persistence and operator recovery across processes.
func (d *DB) ProofArtifactTransaction(ctx context.Context, accountID int64, artifactID string, apply func(*DB) (int64, error)) (int64, error) {
	if accountID <= 0 || artifactID == "" || apply == nil {
		return 0, errors.New("proof artifact attribution is required")
	}
	d = d.ForAccount(accountID)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	sum := sha256.Sum256([]byte(fmt.Sprintf("proof:%d:%s", accountID, artifactID)))
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(sum[:8]))); err != nil {
		return 0, err
	}
	scoped := *d
	scoped.Querier = tx
	id, err := apply(&scoped)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrProofCommitUncertain, err)
	}
	return id, nil
}
