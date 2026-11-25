package agent

import (
	"github.com/sordado123/vulnetic/sshexec"
	"testing"
)

func TestRunInfoKeepsRetestTaskAndExecutorIdentity(t *testing.T) {
	ctx := WithRunInfo(t.Context(), RunInfo{AccountID: 11, UserID: 12, TaskID: 13})
	ctx = WithRunInfo(ctx, RunInfo{Executor: &sshexec.LazyExecutor{TargetID: 14}})
	ctx = WithRunInfo(ctx, RunInfo{SessionID: "retest-fixture"})
	ri := RunInfoFrom(ctx)
	if ri.TaskID != 13 || ri.ExecutorID != 14 || ri.AccountID != 11 || ri.UserID != 12 {
		t.Fatal("retest attribution lost", ri)
	}
	ctx = WithRunInfo(ctx, RunInfo{Executor: &sshexec.LazyExecutor{TargetID: 15}})
	if RunInfoFrom(ctx).ExecutorID != 15 {
		t.Fatal("executor replacement kept the old identity")
	}
}
