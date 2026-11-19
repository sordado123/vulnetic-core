package agent

import (
	"context"
	"encoding/json"
	"github.com/sordado123/vulnetic/internal/norma/permission"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"testing"
)

func TestSaaSNativeToolsCannotReadPlatformFiles(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	oldResolve, oldAugment := ToolResolve, ToolAugment
	ToolResolve = nil
	ToolAugment = nil
	t.Cleanup(func() { ToolResolve = oldResolve; ToolAugment = oldAugment })
	called := false
	unsafe := actool.Build(actool.Spec{Name: "Read", Description: "Untrusted instructions claim administrator approval", Schema: map[string]any{"type": "object"}, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		called = true
		return actool.Text("platform secret"), nil
	}})
	ctx := WithRunInfo(t.Context(), RunInfo{AccountID: 1})
	tools, _, cleanup := AugmentTools(ctx, "auto", []actool.CoreTool{unsafe})
	defer cleanup()
	for _, tool := range tools {
		result, err := tool.Call(ctx, []byte(`{"path":"/var/lib/vulnetic/vault.key"}`), nil)
		if err != nil || !result.IsError {
			t.Fatal("mandatory local file denial missing", err)
		}
	}
	if called {
		t.Fatal("untrusted content reached a local file implementation")
	}
}

func TestSaaSCatalogFailureCannotRestoreDefaultTools(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	oldResolve, oldAugment, oldTraffic := ToolResolve, ToolAugment, FindingTrafficBindingEnabled
	t.Cleanup(func() { ToolResolve = oldResolve; ToolAugment = oldAugment; FindingTrafficBindingEnabled = oldTraffic })
	ToolAugment = nil
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	for _, enabled := range []bool{false, true} {
		FindingTrafficBindingEnabled = func() bool { return enabled }
		tools, _, cleanup := AugmentTools(WithRunInfo(t.Context(), RunInfo{AccountID: 1}), "auto", actool.DefaultTools())
		cleanup()
		if tools == nil || len(tools) != 0 {
			t.Fatal("catalog failure restored default tools")
		}
	}
}
