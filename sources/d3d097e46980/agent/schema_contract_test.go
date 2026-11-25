package agent

import (
	"github.com/sordado123/vulnetic/internal/norma/llm"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"testing"
)

func TestBuiltinModelFacingContracts(t *testing.T) {
	var schemas []llm.ToolSchema
	for _, seed := range BuiltinToolSeeds() {
		schemas = append(schemas, llm.ToolSchema{Name: seed.Key, InputSchema: seed.Schema})
	}
	if err := actool.ValidateToolContracts(schemas); err != nil {
		t.Fatal(err)
	}
}
