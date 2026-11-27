package db

import (
	"strings"
	"testing"
)

func TestUserCredentialCapture(t *testing.T) {
	count := 0
	save := func(in TaskCredentialInput) (TaskCredential, error) {
		count++
		if in.Domain != "example.org" || in.Username != "tester@example.org" || in.Password != "fixture-only" {
			t.Fatal("credential was not preserved")
		}
		return TaskCredential{ID: 42}, nil
	}
	text, err := captureCredentialText("https://example.org/login user: tester@example.org password: fixture-only", "list_chat_credentials", save)
	if err != nil || count != 1 || strings.Contains(text, "fixture-only") || !strings.Contains(text, "VULNETIC_CRED_42_PASSWORD") {
		t.Fatal("capture must save a usable reference", err)
	}
	for _, input := range []string{"Discuss password policy", "password: fixture-only", "https://example.org tester@example.org password: ${VULNETIC_CRED_42_PASSWORD}"} {
		if _, err = captureCredentialText(input, "list_chat_credentials", save); err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatal("ambiguous text or existing references must not be guessed into accounts")
	}
	if _, err = (&DB{}).ConversationCredentials(1); err == nil {
		t.Fatal("missing account accepted")
	}
}
