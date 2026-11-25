package agent

import (
	"context"

	"github.com/sordado123/vulnetic/db"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

// RunInfo identifies WHICH run a tool call belongs to. Tool assembly only receives
// (ctx, agentKey) — the task/exploration ids live in the caller's arguments, not the
// ctx — so anything wired at assembly time (currently the Skill ledger in
// server/assembly.go) has no way to attribute a call to a task. Each run attaches
// its own RunInfo before calling AugmentTools; the wiring closure reads it once and
// captures it, so per-run attribution stays correct without threading parameters
// through the tool layer. Same pattern as TaskClock (see taskclock.go).
//
// Zero value = attribution unknown; every consumer must treat it as optional.
type RunInfo struct {
	Executor      actool.Executor
	ExecutorID    int64
	AccountID     int64
	UserID        int64
	TaskID        int64  // task registry id; 0 for non-task runs (chat sessions)
	ExplorationID int64  // exploration id; 0 when unknown
	IntentID      int64  // worker's intent node; 0 for planner/mainagent/chat
	SessionID     string // chat conversation id; empty for task runs
}

// ResolveRunAccount is supplied by the host for persisted task runs.
var ResolveRunAccount func(taskID int64) int64
var ResolveRunOwner func(taskID int64) (accountID, userID int64)

// explorationID reads a store's exploration id, tolerating a nil store (planner and
// worker runs can be driven without one in tests).
func explorationID(ts *db.ExplorationStore) int64 {
	if ts == nil {
		return 0
	}
	return ts.ID()
}

type runInfoKey struct{}

// WithRunInfo attaches run attribution to ctx.
func WithRunInfo(ctx context.Context, ri RunInfo) context.Context {
	parent := RunInfoFrom(ctx)
	if ri.Executor == nil {
		ri.Executor = parent.Executor
		ri.ExecutorID = parent.ExecutorID
	} else if identified, ok := ri.Executor.(interface{ ExecutionTargetID() int64 }); ok {
		ri.ExecutorID = identified.ExecutionTargetID()
	}
	if ri.SessionID == "" {
		ri.SessionID = parent.SessionID
	}
	if ri.IntentID == 0 {
		ri.IntentID = parent.IntentID
	}
	if ri.ExplorationID == 0 {
		ri.ExplorationID = parent.ExplorationID
	}
	if ri.TaskID == 0 {
		ri.TaskID = parent.TaskID
	}
	if ri.AccountID == 0 {
		ri.AccountID = parent.AccountID
	}
	if ri.UserID == 0 {
		ri.UserID = parent.UserID
	}
	if ri.TaskID > 0 && ResolveRunOwner != nil {
		accountID, userID := ResolveRunOwner(ri.TaskID)
		if ri.AccountID == 0 {
			ri.AccountID = accountID
		}
		if ri.UserID == 0 {
			ri.UserID = userID
		}
	}
	if ri.AccountID == 0 && ri.TaskID > 0 && ResolveRunAccount != nil {
		ri.AccountID = ResolveRunAccount(ri.TaskID)
	}
	return context.WithValue(db.WithExecutionOwner(ctx, ri.AccountID, ri.UserID), runInfoKey{}, ri)
}

// RunInfoFrom reads the RunInfo (zero value if none attached).
func RunInfoFrom(ctx context.Context) RunInfo {
	if v, ok := ctx.Value(runInfoKey{}).(RunInfo); ok {
		return v
	}
	return RunInfo{}
}
