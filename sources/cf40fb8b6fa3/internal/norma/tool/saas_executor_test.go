// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package tool

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaaSLocalExecutorCannotStartProcess(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	handle, err := (LocalExecutor{}).Start(t.Context(), t.TempDir(), nil, "this-command-must-never-be-started", io.Discard)
	if err == nil || handle != nil {
		t.Fatal("local process was admitted in SaaS")
	}
}

func TestSaaSNativeFileToolsDenyBeforeReading(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	directory := t.TempDir()
	secret := "platform-canary-not-for-models"
	file := filepath.Join(directory, "vault.key")
	if err := os.WriteFile(file, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]string{"file_path": file, "path": file})
	for _, tool := range []CoreTool{NewRead(), NewWrite(), NewEdit(), NewMultiEdit(), NewLS(), NewGlob(), NewGrep()} {
		result, err := tool.Call(t.Context(), input, &ToolContext{WorkingDir: directory})
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "policy_denied") || strings.Contains(result.Flatten(), secret) {
			t.Fatalf("local tool escaped mandatory policy: %s", tool.Name())
		}
	}
}
