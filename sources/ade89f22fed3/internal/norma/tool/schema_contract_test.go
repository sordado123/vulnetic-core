package tool

import (
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"testing"
)

func TestToolContractsRejectInvalidWireSchemas(t *testing.T) {
	for _, schema := range []map[string]any{nil, {"type": "object", "properties": nil}, {"type": "array"}, {"type": "object", "required": []string{"missing"}}, {"type": "object", "properties": map[string]any{"rows": map[string]any{"type": "array"}}}} {
		if ValidateToolContracts([]llm.ToolSchema{{Name: "fixture", InputSchema: schema}}) == nil {
			t.Fatalf("accepted invalid schema: %+v", schema)
		}
	}
	if err := ValidateToolContracts(NewRegistry(Build(Spec{Name: "no_args"})).Schemas()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateToolContracts(NewRegistry(DefaultTools()...).Schemas()); err != nil {
		t.Fatal(err)
	}
}
