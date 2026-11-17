package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	"github.com/sordado123/vulnetic/vault"
	"net/http"
	"time"
)

type proofArtifactEnvelope struct {
	Version           int             `json:"version"`
	AccountID         int64           `json:"account_id"`
	TaskID            *int64          `json:"task_id,omitempty"`
	ConversationID    *int64          `json:"conversation_id,omitempty"`
	ExecutorID        *int64          `json:"executor_id,omitempty"`
	AssetID           *int64          `json:"asset_id,omitempty"`
	CheckRunID        *int64          `json:"verification_run_id,omitempty"`
	UserID            int64           `json:"user_id,omitempty"`
	Tool              string          `json:"tool,omitempty"`
	Failed            bool            `json:"failed"`
	CaptureIncomplete bool            `json:"capture_incomplete"`
	RunID             string          `json:"run_id"`
	Input             json.RawMessage `json:"input"`
	Output            string          `json:"output"`
}

func (s *Server) persistProof(ctx context.Context, p db.ExecutionProof) (int64, error) {
	if p.AccountID <= 0 || p.RunID == "" || len(p.Output) > 2<<20 {
		return 0, fmt.Errorf("proof attribution or evidence size is invalid")
	}
	// Cancellation stops execution, but must not discard its final captured evidence.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	envelope := proofArtifactEnvelope{Version: 3, AccountID: p.AccountID, TaskID: p.TaskID, ConversationID: p.ConversationID, ExecutorID: p.ExecutorID, AssetID: p.AssetID, CheckRunID: p.VerificationRunID, UserID: p.UserID, Tool: p.Tool, Failed: p.Failed, CaptureIncomplete: p.CaptureIncomplete, RunID: p.RunID, Input: p.Input, Output: p.Output}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return 0, err
	}
	key, err := s.m.pg.GetOrCreateAccountDEK(p.AccountID, s.vaultKey)
	if err != nil {
		return 0, err
	}
	sealed, err := vault.Seal(key, raw)
	if err != nil {
		return 0, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return 0, err
	}
	p.FullArtifactID = uuid.NewString()
	p = maskedProof(p)
	pg := s.m.pg.ForAccount(p.AccountID)
	if p.TaskID != nil {
		p.Input = pg.RedactTaskJSON(*p.TaskID, p.Input)
		p.Output = pg.RedactTaskText(*p.TaskID, p.Output)
	}
	written := false
	id, err := pg.ProofArtifactTransaction(ctx, p.AccountID, p.FullArtifactID, func(scoped *db.DB) (int64, error) {
		if err := s.writeAccountFile(p.AccountID, "execution-proofs/"+p.FullArtifactID+".vlt", blob); err != nil {
			return 0, err
		}
		written = true
		return scoped.InsertExecutionProof(ctx, p)
	})
	if err == nil {
		return id, nil
	}
	if !written {
		return 0, err
	}
	// A lost INSERT response is ambiguous; absence in a new snapshot cannot prove rollback.
	if errors.Is(err, db.ErrProofCommitUncertain) {
		reconcile, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if pg.QueryRowContext(reconcile, `SELECT id FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, p.AccountID, p.FullArtifactID).Scan(&id) == nil {
			return id, nil
		}
		return 0, fmt.Errorf("proof commit is uncertain; encrypted artifact retained for reconciliation: %w", err)
	}
	root, cleanupErr := s.accountStorage(p.AccountID)
	if cleanupErr == nil {
		cleanupErr = artifactquota.Remove(root, "execution-proofs/"+p.FullArtifactID+".vlt")
		root.Close()
	}
	if cleanupErr != nil {
		return 0, fmt.Errorf("proof insert failed and artifact cleanup requires reconciliation: %w", err)
	}
	return 0, err
}

func maskedProof(p db.ExecutionProof) db.ExecutionProof {
	digest := sha256.Sum256([]byte(p.Output))
	p.Digest = hex.EncodeToString(digest[:])
	p.Input = evidenceredact.JSON(p.Input)
	p.Output = string(evidenceredact.JSON([]byte(p.Output)))
	p.SchemaVersion = 2
	return p
}
func (s *Server) loadProofArtifact(p *db.ExecutionProof) (*proofArtifactEnvelope, error) {
	if p == nil || p.FullArtifactID == "" {
		return nil, errors.New("full execution artifact unavailable")
	}
	if _, err := uuid.Parse(p.FullArtifactID); err != nil {
		return nil, errors.New("invalid artifact identity")
	}
	blob, err := s.readAccountFile(p.AccountID, "execution-proofs/"+p.FullArtifactID+".vlt")
	if err != nil {
		return nil, err
	}
	var sealed vault.Sealed
	if err = json.Unmarshal(blob, &sealed); err != nil {
		return nil, err
	}
	key, err := s.m.pg.GetOrCreateAccountDEK(p.AccountID, s.vaultKey)
	if err != nil {
		return nil, err
	}
	raw, err := vault.Open(key, sealed)
	if err != nil {
		return nil, err
	}
	var value proofArtifactEnvelope
	if json.Unmarshal(raw, &value) != nil || value.Version < 1 || value.Version > 3 || value.AccountID != p.AccountID || value.RunID != p.RunID || !sameProofOwner(value.TaskID, p.TaskID) || !sameProofOwner(value.ConversationID, p.ConversationID) {
		return nil, errors.New("artifact attribution mismatch")
	}
	if value.Version >= 2 && (!sameProofOwner(value.ExecutorID, p.ExecutorID) || !sameProofOwner(value.AssetID, p.AssetID) || !sameProofOwner(value.CheckRunID, p.VerificationRunID)) {
		return nil, errors.New("artifact executor or verification attribution mismatch")
	}
	if value.Version >= 3 && (value.Tool != p.Tool || value.Failed != p.Failed || value.CaptureIncomplete != p.CaptureIncomplete) {
		return nil, errors.New("artifact execution metadata mismatch")
	}
	digest := sha256.Sum256([]byte(value.Output))
	if hex.EncodeToString(digest[:]) != p.Digest {
		return nil, errors.New("artifact checksum mismatch")
	}
	return &value, nil
}
func sameProofOwner(a, b *int64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func (s *Server) downloadProofArtifact(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 404, "Proof not found")
		return
	}
	accountID, userID, ok := accountFromContext(r.Context())
	if !ok {
		writeErr(w, 401, "Authentication required")
		return
	}
	p, err := s.m.pg.ExecutionProofByID(accountID, id)
	if err != nil {
		writeErr(w, 404, "Proof not found")
		return
	}
	value, err := s.loadProofArtifact(p)
	if err != nil {
		writeErr(w, 503, "Full execution artifact unavailable or invalid")
		return
	}
	if err = s.m.pg.RecordAudit(accountID, userID, "EVIDENCE_DOWNLOAD", fmt.Sprintf("/execution-proofs/%d", id), 200); err != nil {
		writeErr(w, 503, "Audit unavailable")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proof-%d.json"`, id))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, value)
}
func (s *Server) validateProofArtifacts(accountID int64, ids []int64) error {
	for _, id := range ids {
		p, err := s.m.pg.ExecutionProofByID(accountID, id)
		if err != nil {
			return fmt.Errorf("execution proof unavailable")
		}
		if p.Failed || p.CaptureIncomplete {
			return fmt.Errorf("failed or incomplete capture cannot confirm a finding")
		}
		if p.SchemaVersion >= 2 {
			if _, err = s.loadProofArtifact(p); err != nil {
				return fmt.Errorf("full execution artifact failed validation")
			}
		} else if p.Truncated {
			return fmt.Errorf("legacy truncated evidence requires a new execution")
		}
	}
	return nil
}
