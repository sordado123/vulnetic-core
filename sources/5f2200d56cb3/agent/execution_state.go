package agent

import (
	"context"
	"github.com/sordado123/vulnetic/internal/runstate"
)

// StartExecution is wired by the host; run ownership comes only from trusted context.
var StartExecution func(context.Context, RunInfo) (context.Context, error)

func beginExecution(ctx context.Context) (context.Context, bool, error) {
	if runstate.From(ctx) != nil || StartExecution == nil {
		return ctx, false, nil
	}
	next, err := StartExecution(ctx, RunInfoFrom(ctx))
	return next, err == nil, err
}

func operationalErrorSummary(err error) string {
	_, message, recovery := runstate.Classify(err)
	return message + " " + recovery
}
