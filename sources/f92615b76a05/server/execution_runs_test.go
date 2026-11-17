package server

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"github.com/sordado123/vulnetic/internal/runstate"
	"testing"
	"time"
)

func TestExecutionStatusDoesNotRestartOrRenew(t *testing.T) {
	input := []runstate.Snapshot{{ID: "interrupted-fixture", Status: "running", PendingTools: 1, ExecutorID: 91}}
	out := executionRunViews(input)
	if out[0].Status != "interrupted" || out[0].Code != "service_restart" || out[0].ExecutorID != 91 || out[0].PendingTools != 1 {
		t.Fatal(out)
	}
	activeExecutionRuns.Store("active-fixture", true)
	defer activeExecutionRuns.Delete("active-fixture")
	out = executionRunViews([]runstate.Snapshot{{ID: "active-fixture", Status: "running"}})
	if out[0].Status != "running" {
		t.Fatal("live run classified interrupted")
	}
}
func TestDeterministicErrorsNeverRetryWholeWorker(t *testing.T) {
	for _, text := range []string{"policy_denied: protected target", "token_budget_exceeded", "execution_state_unavailable", "dependency_unchanged", "select a verified VPS"} {
		if isRetryableStreamError(errors.New(text)) {
			t.Errorf("deterministic failure retried: %s", text)
		}
	}
}

func TestGatewayErrorTaxonomyIsNotAProviderFailure(t *testing.T) {
	for _, item := range []struct{ err, errorCode string }{{"gateway_unavailable", "gateway_unavailable"}, {"executor_offline", "executor_offline"}, {"executor_expired", "executor_expired"}, {"executor_revoked", "executor_revoked"}, {"execution_policy_unavailable: gateway disconnected", "gateway_unavailable"}} {
		code, _, _ := runstate.Classify(errors.New(item.err))
		if code != item.errorCode {
			t.Errorf("%s classified %s", item.err, code)
		}
	}
}

func TestGatewayReconnectCannotRenewOrCrossOwner(t *testing.T) {
	owner := remoteOwner{4, 10}
	s := &Server{revokedTargets: map[remoteOwner]bool{owner: true}}
	if _, err := s.gatewayRefFor(t.Context(), owner, time.Now().Add(time.Hour), "host"); !errors.Is(err, agentgateway.ErrExecutorRevoked) {
		t.Fatal(err)
	}
	if _, err := s.gatewayRefFor(t.Context(), owner, time.Now().Add(-time.Second), "host"); !errors.Is(err, agentgateway.ErrExecutorExpired) {
		t.Fatal(err)
	}
	s = &Server{agentConnections: map[remoteOwner]*agentConnection{owner: {gatewayRef: "fixture"}}, gatewayOwners: map[string]gatewayOwner{"fixture": {owner: remoteOwner{5, 10}}}}
	if _, err := s.gatewayRefFor(t.Context(), owner, time.Now().Add(time.Hour), "host"); !errors.Is(err, agentgateway.ErrExecutorRevoked) {
		t.Fatal("foreign owner allowed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s = &Server{}
	started := time.Now()
	if _, err := s.gatewayRefFor(ctx, owner, time.Now().Add(time.Hour), "host"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancelled operation kept waiting")
	}
}
