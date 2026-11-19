package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/sshexec"
)

func TestBetaOperatorMetricsContainCountsWithoutCustomerContents(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "accounts", "2", "transcripts")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	secret := "must-never-appear-in-metrics"
	if err := os.WriteFile(filepath.Join(path, "fixture"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{m: &Manager{dir: directory, tasks: map[string]*Task{"1": {ID: "1"}, "2": {ID: "2", Queued: true}, "3": {ID: "3", Status: "done"}, "4": {ID: "4", Paused: true}}}, remoteExecutors: map[*sshexec.LazyExecutor]remoteOwner{nil: {2, 1}}}
	server.evidenceFailures.Add(2)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	linkTestDirectory(t, outside, filepath.Join(directory, "accounts", "3"))
	metrics := server.betaSnapshot()
	if metrics.Running != 1 || metrics.Queued != 1 || metrics.SSH != 1 || metrics.EvidenceFailures != 2 || metrics.Storage["2"] != int64(len(secret)) {
		t.Fatalf("invalid operator counters: %+v", metrics)
	}
	if _, leaked := metrics.Storage["3"]; leaked {
		t.Fatal("metrics followed a directory outside account storage")
	}
	data, err := json.Marshal(metrics)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatal("metrics contain customer data", err)
	}
}
