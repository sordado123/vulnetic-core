package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"github.com/sordado123/vulnetic/internal/reverseagent"
)

func TestWindowsEnrollmentRejectsInvalidIdentity(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/agent/enroll", strings.NewReader(`{"platform":"windows","username":"vnfixture"}`))
	r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	w := httptest.NewRecorder()
	(&Server{}).enrollExecutionAgent(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid Windows host identity accepted: %d %s", w.Code, w.Body.String())
	}
	result := (&Server{}).gatewayEvent(context.Background(), agentgateway.Message{Type: "enroll", Hash: make([]byte, 32), Request: &reverseagent.EnrollmentRequest{Platform: "windows", Username: "invalid/identity"}})
	if result.Error == "" || result.Enrollment != nil {
		t.Fatal("gateway accepted an invalid Windows identity")
	}
}

func TestWindowsEnrollmentRequiresAccount(t *testing.T) {
	t.Setenv("VULNETIC_AGENT_PUBLIC_URL", "https://agent.fixture.invalid")
	r := httptest.NewRequest(http.MethodPost, "/api/execution-agents", strings.NewReader(`{"name":"Windows fixture","lease_seconds":10800,"platform":"windows"}`))
	w := httptest.NewRecorder()
	// No manager or database: an unauthenticated request cannot create credentials.
	(&Server{}).createExecutionAgent(w, r)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("Windows enrollment without account accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestWindowsForegroundCommand(t *testing.T) {
	w := httptest.NewRecorder()
	target := &db.SSHTarget{Preflight: []byte(`{"os":"windows"}`)}
	(&Server{}).executionAgentCommand(w, target, "https://agent.fixture.invalid", "synthetic-enrollment-secret", 10800)
	var result struct {
		Command  string `json:"command"`
		Lifetime int    `json:"lease_seconds"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Lifetime != 10800 || !strings.Contains(result.Command, "& $binary -connect") || !strings.Contains(result.Command, "synthetic-enrollment-secret") || strings.Contains(result.Command, "-install") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("foreground command contract failed: %d", w.Code)
	}
}
