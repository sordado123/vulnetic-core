package guard

import (
	"context"
	"github.com/sordado123/vulnetic/intercept"
	"testing"
)

func TestSaaSPolicyPrecedesModelApproval(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	consulted := false
	g := NewWithResolver(func(context.Context) *intercept.Interceptor { consulted = true; return nil })
	for _, tool := range []string{"Bash", "Write", "mcp__custom__request"} {
		blocked, _, _ := g.Hooks().PreToolUse(t.Context(), tool, []byte(`{"command":"curl https://vulnetic.site"}`))
		if !blocked {
			t.Fatalf("protected operation accepted: %s", tool)
		}
	}
	if consulted {
		t.Fatal("tenant rules/model approval were consulted before mandatory denial")
	}
	blocked, _, _ := g.Hooks().PreToolUse(t.Context(), "Bash", []byte(`{"command":"curl http://192.168.5.10"}`))
	if blocked {
		t.Fatal("private customer target was blocked")
	}
}
