package agent

import (
	"context"
	"encoding/json"
	"testing"

	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestDecorateToolEmptyObjectSchema(t *testing.T) {
	for _, properties := range []any{nil, map[string]any(nil)} {
		original := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		base := actool.Build(actool.Spec{Name: "empty-object", Schema: original})
		decorated := DecorateTool(base, "Account description", original)
		raw, err := json.Marshal(decorated.InputSchema())
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err = json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		if _, ok := schema["properties"].(map[string]any); !ok {
			t.Fatalf("properties serialized as null: %s", raw)
		}
		if schema["additionalProperties"] != false || decorated.Description() != "Account description" {
			t.Fatal("normalization changed account metadata or restrictions")
		}
		before, _ := json.Marshal(original)
		if string(before) != `{"additionalProperties":false,"properties":null,"type":"object"}` {
			t.Fatal("normalization mutated the source schema")
		}
	}
}

// TestBuiltinToolSeeds ensures the catalog builds from a nil-store ToolSet without
// panicking, has stable keys, unions agent bindings, and carries real descriptions.
func TestBuiltinToolSeeds(t *testing.T) {
	seeds := BuiltinToolSeeds()
	if len(seeds) == 0 {
		t.Fatal("no seeds")
	}
	byKey := map[string]ToolSeed{}
	for _, s := range seeds {
		if s.Key == "" || s.Desc == "" {
			t.Errorf("seed %q missing key/desc", s.Key)
		}
		byKey[s.Key] = s
	}
	// record_fact is bound to worker (also mainagent, which can log confirmed facts).
	rf, ok := byKey["record_fact"]
	hasWorker := false
	for _, a := range rf.Agents {
		if a == "worker" {
			hasWorker = true
		}
	}
	if !ok || !hasWorker {
		t.Errorf("record_fact agents = %v, want to include worker", rf.Agents)
	}
	// add_task_scope is bound to the planner (deliberate scope widening).
	if ts, ok := byKey["add_task_scope"]; !ok || len(ts.Agents) == 0 {
		t.Errorf("add_task_scope not seeded / has no agent binding: %v", ts.Agents)
	}
	for _, k := range []string{"Bash", "sleep"} {
		seed, ok := byKey[k]
		if !ok || len(seed.Agents) != 4 || seed.Agents[0] != "auto" || seed.Agents[1] != "pentest" || seed.Agents[2] != "worker" || seed.Agents[3] != "retester" {
			t.Errorf("execution tool %s bindings = %v", k, seed.Agents)
		}
	}
	for _, k := range []string{"Read", "Write", "Edit", "Grep"} {
		if _, ok := byKey[k]; ok {
			t.Errorf("local tool %q should not be seeded", k)
		}
	}
}

// TestDecorateToolInjectsDefaults verifies a schema "default" fills a missing param
// before the underlying handler runs, and an explicitly-provided value is kept.
func TestDecorateToolInjectsDefaults(t *testing.T) {
	var seen map[string]any
	base := actool.Build(actool.Spec{
		Name: "probe", Description: "orig",
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			_ = json.Unmarshal(in, &seen)
			return actool.Text("ok"), nil
		},
	})
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"limit": map[string]any{"type": "integer", "description": "n", "default": float64(3)},
		"q":     map[string]any{"type": "string", "description": "query"},
	}}
	dec := DecorateTool(base, "new desc", schema)
	if dec.Description() != "new desc" {
		t.Errorf("description = %q", dec.Description())
	}

	// limit omitted → default 3 injected; q kept.
	if _, err := dec.Call(context.Background(), json.RawMessage(`{"q":"x"}`), nil); err != nil {
		t.Fatal(err)
	}
	if seen["limit"] != float64(3) || seen["q"] != "x" {
		t.Errorf("injected = %v, want limit=3 q=x", seen)
	}

	// limit provided → default does NOT override.
	if _, err := dec.Call(context.Background(), json.RawMessage(`{"limit":9}`), nil); err != nil {
		t.Fatal(err)
	}
	if seen["limit"] != float64(9) {
		t.Errorf("limit = %v, want 9 (no override)", seen["limit"])
	}
}
