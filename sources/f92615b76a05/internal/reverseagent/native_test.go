package reverseagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCommandValidation(t *testing.T) {
	valid := NativeCommand{Kind: "exec", Command: "Write-Output 'fixture'", Env: []string{"X=a'b"}}
	decoded, err := DecodeNative(EncodeNative(valid))
	if err != nil || decoded.Command != valid.Command {
		t.Fatal(err)
	}
	for _, value := range []string{"echo unstructured", NativePrefix + "!", EncodeNative(NativeCommand{Kind: "local-exec"}), strings.Repeat("x", (1<<20)+1)} {
		if _, err = DecodeNative(value); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}

func TestNativeUploadIntegrityAndPreservation(t *testing.T) {
	dir := t.TempDir()
	data := []byte("synthetic evidence\n")
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])
	var ack bytes.Buffer
	if err := nativeUpload(t.Context(), dir, "proof.txt", expected, bytes.NewReader(data), &ack); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Path string `json:"path"`
		Hash string `json:"sha256"`
	}
	if json.Unmarshal(ack.Bytes(), &result) != nil || result.Hash != expected {
		t.Fatal("invalid acknowledgement")
	}
	if err := nativeUpload(t.Context(), dir, "proof.txt", expected, bytes.NewReader(data), &ack); err != nil {
		t.Fatal("identical restore rejected", err)
	}
	if err := nativeUpload(t.Context(), dir, "proof.txt", "", strings.NewReader("overwrite"), &ack); err == nil {
		t.Fatal("existing evidence overwritten")
	}
	for _, name := range []string{"../escape", "C:escape", "sub/file", "..", "bad\\file"} {
		if err := nativeUpload(t.Context(), dir, name, "", bytes.NewReader(data), &ack); err == nil {
			t.Fatal("unsafe name accepted", name)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := nativeUpload(cancelled, dir, "cancelled.txt", "", bytes.NewReader(data), &ack); err == nil {
		t.Fatal("cancelled upload committed")
	}
	if err := nativeUpload(t.Context(), dir, "bad-hash.txt", strings.Repeat("0", 64), bytes.NewReader(data), &ack); err == nil {
		t.Fatal("corrupt transfer accepted")
	}
	preserved, err := os.ReadFile(filepath.Join(dir, "uploads", "proof.txt"))
	if err != nil || !bytes.Equal(preserved, data) {
		t.Fatal("original evidence changed", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "uploads"))
	if err != nil || len(entries) != 1 {
		t.Fatal("failed upload left files", entries, err)
	}
}
