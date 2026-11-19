package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type EvidenceQuote struct {
	ProofID          int64  `json:"proof_id,omitempty"`
	TrafficBindingID int64  `json:"traffic_binding_id,omitempty"`
	Side             string `json:"side,omitempty"`
	Quote            string `json:"quote"`
	Status           string `json:"status,omitempty"`
}
type FindingEvidenceReview struct {
	ID                  int64           `json:"id"`
	EvidenceVersion     int64           `json:"evidence_version"`
	Current             bool            `json:"current"`
	Actor               string          `json:"actor"`
	Counterevidence     string          `json:"counterevidence"`
	ConfidenceRationale string          `json:"confidence_rationale"`
	Quotes              []EvidenceQuote `json:"quotes"`
	CreatedAt           time.Time       `json:"created_at"`
}

func (d *DB) SaveFindingEvidenceReview(ctx context.Context, accountID, findingID, version int64, actor string, review *FindingEvidenceReview) error {
	d = d.ForAccount(accountID)
	raw, err := json.Marshal(review)
	if err != nil {
		return err
	}
	sealed, err := d.sealSecret(accountID, string(raw))
	if err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, `SELECT evidence_version FROM findings WHERE account_id=$1 AND id=$2 FOR UPDATE`, accountID, findingID).Scan(&current); err != nil {
		return err
	}
	if current != version {
		return ErrEvidenceConflict
	}
	if err = tx.QueryRowContext(ctx, `INSERT INTO finding_evidence_reviews(account_id,finding_id,evidence_version,actor,payload) VALUES($1,$2,$3,$4,$5) RETURNING id,created_at`, accountID, findingID, version, actor, sealed).Scan(&review.ID, &review.CreatedAt); err != nil {
		return err
	}
	review.EvidenceVersion = version
	review.Actor = actor
	review.Current = true
	return tx.Commit()
}
func (d *DB) FindingEvidenceReview(ctx context.Context, accountID, findingID int64) (*FindingEvidenceReview, error) {
	d = d.ForAccount(accountID)
	var r FindingEvidenceReview
	var sealed string
	err := d.QueryRowContext(ctx, `SELECT r.id,r.evidence_version,r.actor,r.created_at,r.payload,r.evidence_version=f.evidence_version FROM finding_evidence_reviews r JOIN findings f ON f.id=r.finding_id AND f.account_id=r.account_id WHERE r.account_id=$1 AND r.finding_id=$2 ORDER BY r.id DESC LIMIT 1`, accountID, findingID).Scan(&r.ID, &r.EvidenceVersion, &r.Actor, &r.CreatedAt, &sealed, &r.Current)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := d.openSecret(accountID, sealed)
	if err != nil {
		return nil, err
	}
	var body FindingEvidenceReview
	if err = json.Unmarshal([]byte(plain), &body); err != nil {
		return nil, err
	}
	r.Counterevidence = body.Counterevidence
	r.ConfidenceRationale = body.ConfidenceRationale
	r.Quotes = body.Quotes
	return &r, nil
}
