package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestBetaProofArtifactTransactionRollbackAndConcurrentRecovery(t *testing.T) {
	d := betaTestDB(t)
	a := betaAccount(t, d, "proof-transaction")
	d.ConfigureVault(bytes.Repeat([]byte{41}, 32), true)
	task, err := d.CreateTaskWithOptions("Proof transaction fixture", "Local fixture", TaskCreateOptions{AccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM execution_proofs WHERE account_id=$1`, a.ID) })
	p := ExecutionProof{AccountID: a.ID, TaskID: &task.ID, RunID: "recovery-fixture", Tool: "fixture", Input: json.RawMessage(`{}`), Output: "captured fixture", FullArtifactID: uuid.NewString()}
	rejected := errors.New("fixture rejected")
	_, err = d.ProofArtifactTransaction(t.Context(), a.ID, p.FullArtifactID, func(scoped *DB) (int64, error) {
		if _, err := scoped.InsertExecutionProof(t.Context(), p); err != nil {
			return 0, err
		}
		return 0, rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatal("callback rejection was lost", err)
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, a.ID, p.FullArtifactID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected transaction retained a proof", count, err)
	}
	type result struct {
		id  int64
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 8)
	for range 8 {
		go func() {
			<-start
			id, err := d.ProofArtifactTransaction(t.Context(), a.ID, p.FullArtifactID, func(scoped *DB) (int64, error) {
				var existing int64
				err := scoped.QueryRowContext(t.Context(), `SELECT id FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, a.ID, p.FullArtifactID).Scan(&existing)
				if err == nil {
					return existing, nil
				}
				if !errors.Is(err, sql.ErrNoRows) {
					return 0, err
				}
				return scoped.InsertExecutionProof(t.Context(), p)
			})
			results <- result{id, err}
		}()
	}
	close(start)
	var restored int64
	for range 8 {
		r := <-results
		if r.err != nil || r.id <= 0 {
			t.Error("concurrent recovery failed", r.err)
			continue
		}
		if restored != 0 && restored != r.id {
			t.Error("concurrent recovery returned different proofs")
		}
		restored = r.id
	}
	if err = d.QueryRow(`SELECT count(*) FROM execution_proofs WHERE account_id=$1 AND full_artifact_id=$2`, a.ID, p.FullArtifactID).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent recovery duplicated proof", count, err)
	}
}
