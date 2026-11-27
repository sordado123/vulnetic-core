package report

import (
	"strings"
	"testing"
)

func TestCSVFormulaCellsAreNeutralized(t *testing.T) {
	for _, value := range []string{"=SUM(A1)", "  +1", "-2", "@formula", "\tvalue", "line\rbreak"} {
		if !strings.HasPrefix(safeCSVCell(value), "'") {
			t.Fatalf("unsafe cell %q", value)
		}
	}
	if safeCSVCell("ordinary text") != "ordinary text" {
		t.Fatal("ordinary text changed")
	}
}
