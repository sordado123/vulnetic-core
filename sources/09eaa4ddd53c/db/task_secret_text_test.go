package db

import (
	"strings"
	"testing"
)

func TestProtectedBriefSeparatesExplicitSecret(t *testing.T) {
	d, g, creds, err := protectedBrief("Review https://fixture.invalid", "User tester@fixture.invalid; senha fornecida pelo operador (fixture-only-123).", nil)
	if err != nil || len(creds) != 1 || creds[0].Password != "fixture-only-123" || strings.Contains(d+g, "fixture-only-123") {
		t.Fatal("briefing and secret were not separated", err)
	}
	if _, _, _, err = protectedBrief("review", "password=fixture-only-123", nil); err == nil {
		t.Fatal("ambiguous credential was silently assigned")
	}
}
