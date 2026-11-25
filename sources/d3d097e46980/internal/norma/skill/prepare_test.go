// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package skill

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPrepareSkillChangesDirectoryBeforeInjection(t *testing.T) {
	registry := NewRegistry(Skill{Name: "fixture", Dir: "/platform/private", Instructions: "python3 ${SKILL_DIR}/run.py"})
	registry.Prepare = func(_ context.Context, value Skill) (Skill, error) { value.Dir = "/vps/fixture"; return value, nil }
	result, err := registry.Tool().Call(t.Context(), []byte(`{"name":"fixture"}`), nil)
	if err != nil || result.IsError || len(result.Extra) != 1 {
		t.Fatal("skill did not load", err)
	}
	text := result.Extra[0].Text()
	if !strings.Contains(text, "/vps/fixture/run.py") || strings.Contains(text, "/platform/private") {
		t.Fatal("local path reached the agent", text)
	}
	invoked := false
	registry.OnInvoke = func(Skill) string { invoked = true; return "" }
	registry.Prepare = func(_ context.Context, value Skill) (Skill, error) { return value, errors.New("VPS unavailable") }
	result, err = registry.Tool().Call(t.Context(), []byte(`{"name":"fixture"}`), nil)
	if err != nil || !result.IsError || len(result.Extra) != 0 || invoked {
		t.Fatal("failed preparation injected instructions or unlocked tools")
	}
}
