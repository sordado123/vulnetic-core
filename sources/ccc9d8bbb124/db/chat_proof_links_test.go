package db

import (
	"context"
	"testing"
)

func TestChatProofLinksRejectMissingAttribution(t *testing.T) {
	for _, account := range []int64{0, 1} {
		d := (&DB{}).ForAccount(account)
		if err := d.LinkConversationProofs(context.Background(), 1, 0, 7, 9, []int64{1}, "existing chat evidence"); err == nil {
			t.Fatal("link accepted without authenticated reviewer")
		}
		if err := d.LinkConversationProofs(context.Background(), 1, 1, 0, 9, []int64{1}, "existing chat evidence"); err == nil {
			t.Fatal("link accepted without original conversation")
		}
	}
	if err := (&DB{}).ForAccount(2).LinkConversationProofs(context.Background(), 1, 1, 7, 9, []int64{1}, "existing chat evidence"); err == nil {
		t.Fatal("cross-account link accepted")
	}
}
