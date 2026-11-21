package agent

import (
	"encoding/json"
	"testing"
)

func TestNoArgumentToolsDoNotRequireEmptyProperty(t *testing.T) {
	ts := NewToolSet(nil, "")
	for _, tool := range []interface{ InputSchema() map[string]any }{ts.listTaskCredentials()} {
		raw, err := json.Marshal(tool.InputSchema())
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err = json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		if required, ok := schema["required"].([]any); ok && len(required) != 0 {
			t.Fatalf("empty tool has required properties: %s", raw)
		}
	}
	schema := obj(map[string]any{"name": str("name")}, "", "name")
	if required := schema["required"].([]string); len(required) != 1 || required[0] != "name" {
		t.Fatal(required)
	}
}
