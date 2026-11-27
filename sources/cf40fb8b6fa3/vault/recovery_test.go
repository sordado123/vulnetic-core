package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMasterKeyReadFailureNeverCreatesReplacement(t *testing.T) {
	t.Setenv(masterKeyEnv, "")
	directory := t.TempDir()
	path := filepath.Join(directory, masterKeyFile)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateMasterKey(directory); err == nil {
		t.Fatal("read failure accepted")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatal("key location replaced")
	}
}
