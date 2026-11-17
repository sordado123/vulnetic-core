package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/db"
)

func TestProofPreviewRemasksLegacyHeadersWithoutChangingOriginal(t *testing.T) {
	input := json.RawMessage(`{"command":"printf 'fixture\\nAuthorization: Basic legacy-fixture-secret\\n'"}`)
	before := string(input)
	proofs := []db.ExecutionProof{{ID: 8, Digest: "original-evidence-digest", FullArtifactID: "original-encrypted-artifact", ExecutorID: new(int64(19)), Input: input, Output: "Authorization: Basic legacy-fixture-secret\noriginal preview context"}}
	redactProofPreviews(proofs)
	p := proofs[0]
	if strings.Contains(string(p.Input), "legacy-fixture-secret") || strings.Contains(p.Output, "legacy-fixture-secret") {
		t.Fatal("legacy credential escaped preview masking")
	}
	if string(input) != before || p.Digest != "original-evidence-digest" || p.FullArtifactID != "original-encrypted-artifact" || *p.ExecutorID != 19 {
		t.Fatal("masking changed original evidence or attribution")
	}
	digest := sha256.Sum256([]byte(p.Output))
	if p.PreviewDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("response preview checksum was not updated")
	}
}
