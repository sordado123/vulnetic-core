package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/vault"
)

type ProofReconciliation struct {
	ArtifactID string `json:"artifact_id"`
	ProofID    int64  `json:"proof_id,omitempty"`
	Status     string `json:"status"`
}

// ReconcileProofArtifacts is operator-only: it starts no server, engine or scheduler.
// It never deletes artifacts and never changes a finding or a verifier verdict.
func ReconcileProofArtifacts(ctx context.Context, pg *db.DB, key []byte, dataDir string, accountID int64, recover bool) ([]ProofReconciliation, error) {
	if accountID <= 0 || len(key) != 32 {
		return nil, errors.New("account and existing vault key are required")
	}
	s := &Server{m: &Manager{pg: pg, dir: dataDir}, vaultKey: key}
	root, err := s.accountStorage(accountID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "execution-proofs")
	if errors.Is(err, os.ErrNotExist) {
		return []ProofReconciliation{}, nil
	}
	if err != nil {
		return nil, err
	}
	results := []ProofReconciliation{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".vlt") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".vlt")
		if _, err = uuid.Parse(id); err != nil {
			continue
		}
		result := ProofReconciliation{ArtifactID: id}
		_, err = pg.ProofArtifactTransaction(ctx, accountID, id, func(scoped *db.DB) (int64, error) {
			var existing int64
			e := scoped.QueryRowContext(ctx, `SELECT id FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, accountID, id).Scan(&existing)
			if e == nil {
				result.ProofID = existing
				result.Status = "registered"
				return existing, nil
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return 0, e
			}
			blob, e := s.readAccountFile(accountID, "execution-proofs/"+entry.Name())
			if e != nil {
				return 0, e
			}
			var sealed vault.Sealed
			if json.Unmarshal(blob, &sealed) != nil {
				return 0, errors.New("invalid sealed artifact")
			}
			dek, e := pg.GetOrCreateAccountDEK(accountID, key)
			if e != nil {
				return 0, e
			}
			raw, e := vault.Open(dek, sealed)
			if e != nil {
				return 0, errors.New("artifact authentication failed")
			}
			var v proofArtifactEnvelope
			if json.Unmarshal(raw, &v) != nil || v.AccountID != accountID {
				return 0, errors.New("artifact attribution mismatch")
			}
			if v.Version != 3 {
				result.Status = "legacy_requires_manual_review"
				return 0, nil
			}
			if v.RunID == "" || v.Tool == "" || len(v.Input) == 0 || len(v.Output) > 2<<20 {
				return 0, errors.New("artifact metadata incomplete")
			}
			if v.CheckRunID != nil {
				result.Status = "verifier_requires_manual_review"
				return 0, nil
			}
			result.Status = "recoverable"
			if !recover {
				return 0, nil
			}
			p := maskedProof(db.ExecutionProof{AccountID: accountID, UserID: v.UserID, TaskID: v.TaskID, ConversationID: v.ConversationID, ExecutorID: v.ExecutorID, AssetID: v.AssetID, RunID: v.RunID, Tool: v.Tool, Input: v.Input, Output: v.Output, Failed: v.Failed, CaptureIncomplete: v.CaptureIncomplete, FullArtifactID: id})
			proofID, e := scoped.InsertExecutionProof(ctx, p)
			if e != nil {
				return 0, e
			}
			if e = scoped.RecordAudit(accountID, 0, "PROOF_RECOVER", fmt.Sprintf("/execution-proofs/%d", proofID), 201); e != nil {
				return 0, e
			}
			result.Status = "recovered"
			result.ProofID = proofID
			return proofID, nil
		})
		if err != nil {
			return results, fmt.Errorf("reconciliation stopped at artifact %s: %w", id, err)
		}
		results = append(results, result)
	}
	return results, nil
}
