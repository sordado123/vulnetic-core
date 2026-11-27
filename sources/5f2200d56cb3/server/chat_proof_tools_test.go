package server

import (
	"encoding/json"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestProofTaskIDAcceptsNumericAndStringIDs(t *testing.T) {
	for _, raw := range []string{`17`, `"17"`} {
		var id proofTaskID
		if err := json.Unmarshal([]byte(raw), &id); err != nil || id != 17 {
			t.Fatalf("%s: id=%d err=%v", raw, id, err)
		}
		for _, spec := range (&Server{}).chatProofTools() {
			if spec.Name() == "list_task_execution_proofs" {
				if err := tool.ValidateInput(spec.InputSchema(), []byte(`{"task_id":`+raw+`}`)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, raw := range []string{`0`, `-1`, `1.5`, `null`, `true`, `{}`, `"17;echo x"`, `9223372036854775808`} {
		var id proofTaskID
		if json.Unmarshal([]byte(raw), &id) == nil {
			t.Fatalf("accepted invalid task ID %s", raw)
		}
	}
}
