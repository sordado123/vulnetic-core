package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"time"
)

var ErrProofCommitUncertain = errors.New("execution proof commit could not be confirmed")

type ExecutionProof struct {
	CaptureIncomplete bool            `json:"capture_incomplete"`
	AssetID           *int64          `json:"asset_id,omitempty"`
	ExecutorID        *int64          `json:"executor_id,omitempty"`
	VerificationRunID *int64          `json:"verification_run_id,omitempty"`
	FullArtifactID    string          `json:"full_artifact_id,omitempty"`
	PreviewDigest     string          `json:"preview_sha256,omitempty"`
	Failed            bool            `json:"failed"`
	SchemaVersion     int             `json:"schema_version"`
	ID                int64           `json:"id"`
	AccountID         int64           `json:"-"`
	UserID            int64           `json:"-"`
	TaskID            *int64          `json:"task_id,omitempty"`
	ConversationID    *int64          `json:"conversation_id,omitempty"`
	RunID             string          `json:"run_id"`
	Tool              string          `json:"tool"`
	Input             json.RawMessage `json:"input"`
	Output            string          `json:"output"`
	Digest            string          `json:"sha256"`
	Truncated         bool            `json:"truncated"`
	CreatedAt         time.Time       `json:"created_at"`
}

func (d *DB) RecordExecutionProof(ctx context.Context, p ExecutionProof) error {
	_, err := d.InsertExecutionProof(ctx, p)
	return err
}
func (d *DB) InsertExecutionProof(ctx context.Context, p ExecutionProof) (id int64, err error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(p.AccountID)
	}
	if p.AccountID <= 0 || p.RunID == "" || len(p.Input) == 0 || strings.TrimSpace(p.Output) == "" {
		return 0, errors.New("execution attribution is required")
	}
	if d.hasAccount && d.accountID != p.AccountID {
		return 0, errors.New("account mismatch")
	}
	if p.UserID != 0 {
		var owned bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND account_id=$2)`, p.UserID, p.AccountID).Scan(&owned); err != nil {
			return 0, err
		}
		if !owned {
			return 0, errors.New("execution actor does not belong to account")
		}
	}
	if p.TaskID != nil {
		var owner int64
		if err := d.QueryRow(`SELECT account_id FROM tasks WHERE id=$1`, p.TaskID).Scan(&owner); err != nil || owner != p.AccountID {
			return 0, ErrTaskNotFound
		}
	}
	if p.ConversationID != nil {
		c, err := d.ForAccount(p.AccountID).GetConversation(*p.ConversationID)
		if err != nil || c == nil {
			return 0, errors.New("conversation not found")
		}
	}
	if p.TaskID == nil && p.ConversationID == nil {
		return 0, errors.New("task or conversation is required")
	}
	if p.AssetID != nil {
		var owned bool
		err = d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1 AND account_id=$2 AND ($3::bigint IS NULL OR $3=ANY(task_ids)))`, *p.AssetID, p.AccountID, p.TaskID).Scan(&owned)
		if err != nil || !owned {
			return 0, errors.New("proof asset does not belong to task")
		}
	}
	if p.VerificationRunID != nil {
		var owned bool
		err = d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cve_check_runs WHERE id=$1 AND account_id=$2 AND task_id=$3 AND asset_id=$4 AND executor_id=$5 AND status='running')`, *p.VerificationRunID, p.AccountID, p.TaskID, p.AssetID, p.ExecutorID).Scan(&owned)
		if err != nil || !owned {
			return 0, errors.New("proof does not belong to an active verifier run")
		}
	}
	if p.Digest == "" {
		digest := sha256.Sum256([]byte(p.Output))
		p.Digest = hex.EncodeToString(digest[:])
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = 1
	}
	p.Truncated = p.Truncated || strings.Contains(p.Output, "characters truncated]") || strings.Contains(p.Output, "<persisted-output>")
	if len(p.Output) > 256<<10 {
		p.Output = strings.ToValidUTF8(p.Output[:256<<10], "")
		p.Truncated = true
	}
	previewHash := sha256.Sum256([]byte(p.Output))
	p.PreviewDigest = hex.EncodeToString(previewHash[:])
	payload, err := json.Marshal(map[string]any{"input": p.Input, "output": p.Output})
	if err != nil {
		return 0, err
	}
	sealed, err := d.sealSecret(p.AccountID, string(payload))
	if err != nil {
		return 0, err
	}
	err = d.QueryRowContext(ctx, `INSERT INTO execution_proofs(account_id,task_id,conversation_id,run_id,tool,payload,digest,truncated,user_id,asset_id,executor_id,verification_run_id,full_artifact_id,preview_digest,failed,schema_version,capture_incomplete) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`, p.AccountID, p.TaskID, p.ConversationID, p.RunID, p.Tool, sealed, p.Digest, p.Truncated, nullIfZero(p.UserID), p.AssetID, p.ExecutorID, p.VerificationRunID, p.FullArtifactID, p.PreviewDigest, p.Failed, p.SchemaVersion, p.CaptureIncomplete).Scan(&id)
	if err != nil {
		var rejected *pgconn.PgError
		if !errors.As(err, &rejected) {
			return 0, fmt.Errorf("%w: %w", ErrProofCommitUncertain, err)
		}
	}
	return id, err
}
func (d *DB) ExecutionProofs(accountID int64, taskID *int64, conversationID *int64) ([]ExecutionProof, error) {
	return d.ExecutionProofsPage(accountID, taskID, conversationID, 0, 100)
}
func (d *DB) ExecutionProofsPage(accountID int64, taskID, conversationID *int64, before int64, limit int) ([]ExecutionProof, error) {
	if limit < 1 || limit > 101 {
		limit = 26
	}
	if before < 0 {
		return nil, errors.New("invalid proof cursor")
	}
	if d.hasAccount && d.accountID != accountID {
		return nil, errors.New("account mismatch")
	}
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	rows, err := d.Query(`SELECT id,task_id,conversation_id,run_id,tool,payload,digest,truncated,created_at,asset_id,executor_id,verification_run_id,full_artifact_id,preview_digest,failed,schema_version,capture_incomplete FROM execution_proofs WHERE account_id=$1 AND (($2::bigint IS NOT NULL AND (task_id=$2 OR EXISTS(SELECT 1 FROM task_execution_proof_links l WHERE l.account_id=execution_proofs.account_id AND l.task_id=$2 AND l.proof_id=execution_proofs.id))) OR ($3::bigint IS NOT NULL AND conversation_id=$3)) AND ($4::bigint=0 OR id<$4) ORDER BY id DESC LIMIT $5`, accountID, taskID, conversationID, before, limit)
	if err != nil {
		return nil, err
	}
	return d.readExecutionProofs(rows, accountID)
}

// TaskExecutionProofsPage exports the entire history in bounded pages, not just the UI's latest 100.
func (d *DB) TaskExecutionProofsPage(accountID, taskID, afterID int64) ([]ExecutionProof, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if d.hasAccount && d.accountID != accountID {
		return nil, errors.New("account mismatch")
	}
	rows, err := d.Query(`SELECT id,task_id,conversation_id,run_id,tool,payload,digest,truncated,created_at,asset_id,executor_id,verification_run_id,full_artifact_id,preview_digest,failed,schema_version,capture_incomplete FROM execution_proofs WHERE account_id=$1 AND (task_id=$2 OR EXISTS(SELECT 1 FROM task_execution_proof_links l WHERE l.account_id=execution_proofs.account_id AND l.task_id=$2 AND l.proof_id=execution_proofs.id)) AND id>$3 ORDER BY id LIMIT 10`, accountID, taskID, afterID)
	if err != nil {
		return nil, err
	}
	return d.readExecutionProofs(rows, accountID)
}
func (d *DB) readExecutionProofs(rows *sql.Rows, accountID int64) ([]ExecutionProof, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	var err error
	defer rows.Close()
	out := []ExecutionProof{}
	for rows.Next() {
		p := ExecutionProof{AccountID: accountID}
		var sealed string
		if err = rows.Scan(&p.ID, &p.TaskID, &p.ConversationID, &p.RunID, &p.Tool, &sealed, &p.Digest, &p.Truncated, &p.CreatedAt, &p.AssetID, &p.ExecutorID, &p.VerificationRunID, &p.FullArtifactID, &p.PreviewDigest, &p.Failed, &p.SchemaVersion, &p.CaptureIncomplete); err != nil {
			return nil, err
		}
		plain, err := d.openSecret(accountID, sealed)
		if err != nil {
			return nil, err
		}
		var payload struct {
			Input  json.RawMessage `json:"input"`
			Output string          `json:"output"`
		}
		if err = json.Unmarshal([]byte(plain), &payload); err != nil {
			return nil, err
		}
		p.Input, p.Output = payload.Input, payload.Output
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) VerifyFinding(ctx context.Context, accountID, userID, findingID int64, proofIDs []int64, steps string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	steps = strings.TrimSpace(steps)
	if len(steps) < 10 || len(steps) > 16000 || len(proofIDs) == 0 || len(proofIDs) > 20 || userID <= 0 {
		return errors.New("provide reproduction steps, execution proofs and an authenticated reviewer")
	}
	if d.hasAccount && d.accountID != accountID {
		return errors.New("account mismatch")
	}
	if err := d.ValidateFindingCheckProofs(ctx, accountID, findingID, proofIDs); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owned bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND account_id=$2)`, userID, accountID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return errors.New("reviewer does not belong to account")
	}
	var taskID *int64
	var version int64
	var evidence, summary string
	if err = tx.QueryRow(`SELECT task_id,evidence_version,evidence,summary FROM findings WHERE account_id=$1 AND id=$2 FOR UPDATE`, accountID, findingID).Scan(&taskID, &version, &evidence, &summary); err != nil {
		return ErrFindingNotFound
	}
	if taskID == nil {
		return errors.New("verification requires a task with execution evidence")
	}
	for _, id := range proofIDs {
		var owned bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM execution_proofs WHERE id=$1 AND account_id=$2 AND (task_id=$3 OR EXISTS(SELECT 1 FROM task_execution_proof_links l WHERE l.account_id=execution_proofs.account_id AND l.task_id=$3 AND l.proof_id=execution_proofs.id)) AND NOT failed AND NOT capture_incomplete AND (NOT truncated OR (schema_version>=2 AND full_artifact_id<>'')))`, id, accountID, taskID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return errors.New("execution proof does not belong to this finding's task")
		}
	}
	var verificationID int64
	if err = tx.QueryRow(`INSERT INTO finding_verifications(account_id,finding_id,user_id,steps,evidence_version,source_evidence,source_summary,check_run_id) VALUES($1,$2,$3,$4,$5,$6,$7,(SELECT verification_run_id FROM execution_proofs WHERE id=$8 AND account_id=$1)) RETURNING id`, accountID, findingID, userID, steps, version, evidence, summary, proofIDs[0]).Scan(&verificationID); err != nil {
		return err
	}
	for _, id := range proofIDs {
		if _, err = tx.Exec(`INSERT INTO finding_verification_proofs(verification_id,proof_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, verificationID, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`UPDATE exploration_nodes n SET state='verified' FROM findings f WHERE f.id=$1 AND f.account_id=$2 AND n.id=f.node_id AND n.kind='finding'`, findingID, accountID); err != nil {
		return err
	}
	return tx.Commit()
}

// VerificationProofRef is the light reference to one execution proof linked to a
// finding's verification — enough to name the evidence and offer its download,
// without decrypting the sealed payload the proof viewer handles.
type VerificationProofRef struct {
	ID             int64     `json:"id"`
	Tool           string    `json:"tool"`
	RunID          string    `json:"run_id"`
	CreatedAt      time.Time `json:"created_at"`
	Digest         string    `json:"digest,omitempty"`
	Truncated      bool      `json:"truncated"`
	FullArtifactID string    `json:"full_artifact_id,omitempty"`
}

// FindingPlaybook is the human-readable reproduction record of a verified finding:
// the reviewer-written steps, the claim they confirmed, and the exact execution
// proofs they reviewed — the evidence chain a customer replays. Current is false
// when the finding's evidence changed after this verification (the finding has
// fallen back to candidate), so the UI can mark the playbook as predating it.
type FindingPlaybook struct {
	VerificationID int64                  `json:"verification_id"`
	Steps          string                 `json:"steps"`
	Summary        string                 `json:"summary"`
	VerifiedAt     time.Time              `json:"verified_at"`
	Current        bool                   `json:"current"`
	Proofs         []VerificationProofRef `json:"proofs"`
}

// FindingVerificationPlaybook returns the latest recorded verification for a
// finding as a reproduction playbook, or nil when the finding was never verified.
// Account-scoped; the linked proofs are joined from finding_verification_proofs.
func (d *DB) FindingVerificationPlaybook(ctx context.Context, accountID, findingID int64) (*FindingPlaybook, error) {
	d = d.ForAccount(accountID)
	var pb FindingPlaybook
	err := d.QueryRowContext(ctx, `SELECT v.id, v.steps, v.source_summary, v.created_at,
	 (v.evidence_version=f.evidence_version AND v.source_evidence=f.evidence AND v.source_summary=f.summary) AS current
	 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id AND f.account_id=v.account_id
	 WHERE v.account_id=$1 AND v.finding_id=$2 ORDER BY v.id DESC LIMIT 1`, accountID, findingID).
		Scan(&pb.VerificationID, &pb.Steps, &pb.Summary, &pb.VerifiedAt, &pb.Current)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT p.id,p.tool,p.run_id,p.created_at,p.digest,p.truncated,p.full_artifact_id
	 FROM finding_verification_proofs b JOIN execution_proofs p ON p.id=b.proof_id AND p.account_id=$1
	 WHERE b.verification_id=$2 ORDER BY p.id`, accountID, pb.VerificationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ref VerificationProofRef
		if err := rows.Scan(&ref.ID, &ref.Tool, &ref.RunID, &ref.CreatedAt, &ref.Digest, &ref.Truncated, &ref.FullArtifactID); err != nil {
			return nil, err
		}
		pb.Proofs = append(pb.Proofs, ref)
	}
	return &pb, rows.Err()
}

func (d *DB) ExecutionProofByID(accountID, id int64) (*ExecutionProof, error) {
	d = d.ForAccount(accountID)
	rows, err := d.Query(`SELECT id,task_id,conversation_id,run_id,tool,payload,digest,truncated,created_at,asset_id,executor_id,verification_run_id,full_artifact_id,preview_digest,failed,schema_version,capture_incomplete FROM execution_proofs WHERE id=$1 AND account_id=$2`, id, accountID)
	if err != nil {
		return nil, err
	}
	ps, err := d.readExecutionProofs(rows, accountID)
	if err != nil {
		return nil, err
	}
	if len(ps) != 1 {
		return nil, sql.ErrNoRows
	}
	return &ps[0], nil
}
