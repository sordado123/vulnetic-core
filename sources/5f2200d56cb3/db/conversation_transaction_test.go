package db

import "testing"

func TestConversationUsesCallerTransaction(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	scoped := *d
	scoped.Querier = tx
	c, err := scoped.CreateConversation(LegacyAccountID, "auto", "rollback fixture", nil)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversations WHERE id=$1)`, c.ID).Scan(&exists); err != nil || exists {
		t.Fatal("conversation escaped caller transaction", err)
	}
}
