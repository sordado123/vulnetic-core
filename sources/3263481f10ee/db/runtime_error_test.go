package db

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeOwnerFailureIsNotAnEmptyResult(t *testing.T) {
	cause := errors.New("owner lookup fixture failure")
	root := &DB{runtime: &runtimePools{}, Querier: scopeFailure{cause}}
	scoped := root.runtimeResource("task", 123)
	for _, candidate := range []*DB{scoped, scoped.ForAccount(7)} {
		if err := candidate.QueryRow("unreachable").Scan(new(int)); !errors.Is(err, cause) || !errors.Is(err, ErrRuntimeOwner) {
			t.Fatalf("Scan lost lookup failure: %v", err)
		}
		if _, err := candidate.Query("unreachable"); !errors.Is(err, cause) {
			t.Fatalf("Query: %v", err)
		}
		if _, err := candidate.Exec("unreachable"); !errors.Is(err, cause) {
			t.Fatalf("Exec: %v", err)
		}
		if _, err := candidate.BeginTx(context.Background(), nil); !errors.Is(err, cause) {
			t.Fatalf("Begin: %v", err)
		}
		if _, err := candidate.GetTask(123); !errors.Is(err, cause) {
			t.Fatalf("GetTask hid failure: %v", err)
		}
	}
}
