package db

import (
	"context"
	"errors"
	"testing"
)

func TestFindingPatchRejectsAllFieldsBeforeDatabase(t *testing.T) {
	status, severity := "resolved", "invalid"
	d := &DB{}
	if _, err := d.PatchFinding(context.Background(), 1, FindingPatch{Status: &status, Severity: &severity}, true); !errors.Is(err, ErrInvalidFindingPatch) {
		t.Fatal(err)
	}
}
