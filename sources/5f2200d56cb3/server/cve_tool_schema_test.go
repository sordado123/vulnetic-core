package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/internal/norma/llm"
)

func TestCVEVerifierSchemaOpenAIWire(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "code"
		if legacy {
			name = "persisted-null-properties"
		}
		t.Run(name, func(t *testing.T) {
			tool := (&Server{}).cveVerificationTools()[0]
			if tool.Name() != "list_cve_verifiers" {
				t.Fatal("wrong fixture tool")
			}
			if legacy {
				var schema map[string]any
				if err := json.Unmarshal([]byte(`{"type":"object","properties":null}`), &schema); err != nil {
					t.Fatal(err)
				}
				tool = agent.DecorateTool(tool, "Preserved account description", schema)
			}
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Tools []struct {
						Function struct {
							Name       string         `json:"name"`
							Parameters map[string]any `json:"parameters"`
						} `json:"function"`
					} `json:"tools"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Tools) != 1 {
					http.Error(w, "invalid tool fixture", 400)
					return
				}
				function := request.Tools[0].Function
				properties, ok := function.Parameters["properties"].(map[string]any)
				if function.Name != "list_cve_verifiers" || function.Parameters["type"] != "object" || !ok || len(properties) != 0 {
					http.Error(w, `{"error":{"message":"Invalid schema: properties must be an object"}}`, 400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"schema accepted"},"finish_reason":"stop"}]}`))
			}))
			defer provider.Close()
			client, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAI, BaseURL: provider.URL, APIKey: "synthetic-fixture", Model: "local-schema-fixture"})
			if err != nil {
				t.Fatal(err)
			}
			message, _, _, err := client.Complete(t.Context(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("Validate the tool schema only")}, Tools: []llm.ToolSchema{{Name: tool.Name(), Description: tool.Description(), InputSchema: tool.InputSchema()}}})
			if err != nil || message.Text() != "schema accepted" {
				t.Fatalf("local provider rejected generated schema: %v", err)
			}
		})
	}
}
