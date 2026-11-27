package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/assessment"
	"github.com/sordado123/vulnetic/config"
)

func TestAssessmentKnowledgeAndResearchAccountIsolation(t *testing.T) {
	operator := betaTestDB(t)
	operator.ConfigureVault(bytes.Repeat([]byte{61}, 32), true)
	a := betaAccount(t, operator, "assessment-a")
	b := betaAccount(t, operator, "assessment-b")
	task, err := operator.CreateTaskWithOptions("Assessment fixture", "No model calls", TaskCreateOptions{AccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := operator.InsertExecutionProof(t.Context(), ExecutionProof{AccountID: a.ID, TaskID: &task.ID, RunID: "assessment-fixture", Tool: "Bash", Input: json.RawMessage(`{"command":"fixture"}`), Output: "complete synthetic observation"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := operator.InsertExecutionProof(t.Context(), ExecutionProof{AccountID: a.ID, TaskID: &task.ID, RunID: "assessment-failed-fixture", Tool: "Bash", Input: json.RawMessage(`{"command":"fixture"}`), Output: "failed synthetic observation", Failed: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { operator.Exec(`DELETE FROM execution_proofs WHERE account_id=$1`, a.ID) })
	connections := []struct {
		name string
		db   *DB
	}{{"application_filters", operator}}
	if os.Getenv("VULNETIC_PG_APP_PASSWORD") != "" {
		dsn, err := config.PostgresAppDSN()
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := OpenRuntime(dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { runtime.Close() })
		runtime.ShareVaultFrom(operator)
		connections = append(connections, struct {
			name string
			db   *DB
		}{"runtime_rls", runtime})
	}
	for _, connection := range connections {
		t.Run(connection.name, func(t *testing.T) {
			pg := connection.db.ForAccount(a.ID)
			foreign := connection.db.ForAccount(b.ID)
			fallbacks := []string{"ddgs"}
			if _, err := pg.SaveSearchConfig(t.Context(), AccountSearchPatch{Fallbacks: &fallbacks}); err != nil {
				t.Fatal(err)
			}
			other, err := foreign.SearchConfig()
			if err != nil || len(other.Fallbacks) != 0 {
				t.Fatalf("foreign research settings leaked: %+v %v", other, err)
			}
			check := assessment.Coverage{Profile: "web", Check: "inventory", State: "tested", Note: "Synthetic observation, not finding verification", ProofIDs: []int64{proof}}
			if _, err := foreign.RecordAssessmentCheck(t.Context(), task.ID, check); err == nil {
				t.Fatal("foreign coverage write accepted")
			}
			if _, err := foreign.AssessmentCoverage(task.ID); err == nil {
				t.Fatal("foreign coverage read accepted")
			}
			check.ProofIDs = []int64{failed}
			if _, err := pg.RecordAssessmentCheck(t.Context(), task.ID, check); err == nil {
				t.Fatal("failed execution established coverage")
			}
			check.ProofIDs = []int64{proof}
			errors := make(chan error, 8)
			var workers sync.WaitGroup
			for _, method := range assessment.Methodologies[0].Checks {
				workers.Add(1)
				go func(id string) {
					defer workers.Done()
					c := check
					c.Check = id
					_, err := pg.RecordAssessmentCheck(t.Context(), task.ID, c)
					errors <- err
				}(method.ID)
			}
			workers.Wait()
			close(errors)
			for err := range errors {
				if err != nil {
					t.Fatal(err)
				}
			}
			coverage, err := pg.AssessmentCoverage(task.ID)
			if err != nil || len(coverage) != len(assessment.Methodologies[0].Checks) {
				t.Fatalf("lost concurrent coverage: %+v %v", coverage, err)
			}
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := pg.RecordAssessmentCheck(cancelled, task.ID, check); err == nil {
				t.Fatal("cancelled write accepted")
			}
			note := KnowledgeNote{Category: "inventory", Text: "selected-observation fixture", TaskID: task.ID, ProofID: proof, ExpiresAt: time.Now().Add(time.Hour)}
			if err := foreign.SaveKnowledgeNote(note); err == nil {
				t.Fatal("foreign note accepted")
			}
			if err := pg.SaveKnowledgeNote(note); err != nil {
				t.Fatal(err)
			}
			rows, err := pg.SearchKnowledgeNotes("selected-observation", task.ID, false)
			if err != nil || len(rows) != 1 || rows[0].ProofID != proof {
				t.Fatalf("note provenance lost: %+v %v", rows, err)
			}
			rows, err = foreign.SearchKnowledgeNotes("selected-observation", task.ID, true)
			if err != nil || len(rows) != 0 {
				t.Fatal("foreign knowledge visible", err)
			}
			var stored string
			if err := operator.QueryRow(`SELECT value FROM account_settings WHERE account_id=$1 AND key=$2`, a.ID, fmt.Sprintf("knowledge.note.v1.%d.%d", task.ID, proof)).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(stored, "selected-observation") {
				t.Fatal("knowledge plaintext at rest")
			}
		})
	}
}
