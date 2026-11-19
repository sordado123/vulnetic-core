package server

import (
	"context"
	"encoding/json"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
)

func localOnlyTool(name string) bool { return platformpolicy.LocalTool(name) }

type remoteOnlyTool struct{ actool.CoreTool }

func (t remoteOnlyTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if tc == nil || tc.Executor == nil {
		return actool.Errorf("execution requires a verified VPS; local fallback is disabled"), nil
	}
	switch tc.Executor.(type) {
	case actool.LocalExecutor, *actool.LocalExecutor:
		return actool.Errorf("local execution is disabled"), nil
	}
	return t.CoreTool.Call(ctx, in, tc)
}
