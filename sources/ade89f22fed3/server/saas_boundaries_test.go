package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBetaColdArchivesRemainOperatorOnly(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	server := &Server{}
	handler := server.withSaaSBoundaries(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, path := range []string{"/api/tasks/7/archive", "/api/tasks/archive/batch", "/api/task-archives/2/restore", "/api/task-archives/delete/batch"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("POST", path, nil))
		if response.Code != 409 {
			t.Fatalf("archive mutation %s: %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/task-archives", nil))
	if response.Code != 204 {
		t.Fatal("historical archive metadata should remain consultable")
	}
}
