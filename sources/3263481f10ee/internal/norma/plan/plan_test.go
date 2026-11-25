// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package plan

import (
	"context"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/internal/norma/permission"
	"github.com/sordado123/vulnetic/internal/norma/tool"
)

func TestControllerTransitions(t *testing.T) {
	c := NewController(permission.ModeDefault, permission.ModeAcceptEdits)
	if c.InPlan() {
		t.Fatal("should not start in plan")
	}
	c.Enter()
	if c.Mode() != permission.ModePlan {
		t.Fatalf("mode=%v", c.Mode())
	}
	c.approve()
	if c.Mode() != permission.ModeAcceptEdits {
		t.Fatalf("after approve mode=%v", c.Mode())
	}
}

func TestExitToolApprove(t *testing.T) {
	c := NewController(permission.ModePlan, permission.ModeAcceptEdits)
	exit := ExitTool(c, func(_ context.Context, _ string) (bool, string) { return true, "" })
	res, _ := exit.Call(context.Background(), []byte(`{"plan":"step 1"}`), &tool.ToolContext{})
	if res.IsError || !strings.Contains(res.Flatten(), "approved") {
		t.Fatalf("approve result: %q (err=%v)", res.Flatten(), res.IsError)
	}
	if c.Mode() != permission.ModeAcceptEdits {
		t.Fatalf("mode after approve=%v", c.Mode())
	}
}

func TestExitToolReject(t *testing.T) {
	c := NewController(permission.ModePlan, permission.ModeAcceptEdits)
	exit := ExitTool(c, func(_ context.Context, _ string) (bool, string) { return false, "needs tests" })
	res, _ := exit.Call(context.Background(), []byte(`{"plan":"x"}`), &tool.ToolContext{})
	if !res.IsError || !strings.Contains(res.Flatten(), "needs tests") {
		t.Fatalf("reject result: %q", res.Flatten())
	}
	if c.Mode() != permission.ModePlan {
		t.Fatalf("should stay in plan, mode=%v", c.Mode())
	}
}
