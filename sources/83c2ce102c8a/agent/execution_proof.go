package agent

import (
	"context"
	"encoding/json"

	"github.com/sordado123/vulnetic/db"
)

// The host persists actual tool results; model-authored text never enters here.
var RecordExecutionProof func(context.Context, RunInfo, string, string, json.RawMessage, string, bool) error

func recordExecutionProof(ctx context.Context, runID string, inputs map[string]json.RawMessage, activity db.Activity) error {
	if RecordExecutionProof == nil || activity.Kind != "tool_result" {
		return nil
	}
	return RecordExecutionProof(ctx, RunInfoFrom(ctx), runID, activity.Tool, inputs[activity.ToolUseID], activity.Detail, activity.IsError)
}
