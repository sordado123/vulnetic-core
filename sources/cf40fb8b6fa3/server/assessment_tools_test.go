package server

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
)

func TestAssessmentHostContractsAndMissingExecutor(t *testing.T) {
	s := &Server{}
	tools := append(s.executionAssessmentTools(), s.assessmentCoverageTools()...)
	tools = append(tools, s.knowledgeTools()...)
	tools = append(tools, s.toolWebSearch())
	var schemas []llm.ToolSchema
	for _, tool := range tools {
		schemas = append(schemas, llm.ToolSchema{Name: tool.Name(), InputSchema: tool.InputSchema()})
		if tool.Name() == "inspect_executor" || tool.Name() == "diagnose_executor" || tool.Name() == "run_network_inventory" || tool.Name() == "browser_session" || tool.Name() == "read_web_page" {
			result, err := tool.Call(agent.WithRunInfo(context.Background(), agent.RunInfo{AccountID: 1}), json.RawMessage(`{}`), nil)
			if err != nil || !result.IsError {
				t.Errorf("%s accepted missing remote executor", tool.Name())
			}
		}
	}
	if err := actool.ValidateToolContracts(schemas); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"browser_session", "read_web_page"} {
		if err := platformpolicy.CheckTool(name, json.RawMessage(`{"url":"https://vulnetic.site/"}`)); err == nil {
			t.Fatalf("%s bypassed protected target", name)
		}
	}
}

func TestBrowserActionBoundary(t *testing.T) {
	for _, actions := range [][]browserAction{nil, {{Kind: "evaluate", Value: "arbitrary code"}}, {{Kind: "fill", Selector: "input", EnvKey: "PATH"}}, {{Kind: "fill", Selector: "input", EnvKey: "VULNETIC_CRED_1_PASSWORD", Value: "secret"}}, {{Kind: "click"}}, make([]browserAction, 13)} {
		if validateBrowserActions(actions) == nil {
			t.Fatalf("invalid browser actions accepted: %+v", actions)
		}
	}
	if err := validateBrowserActions([]browserAction{{Kind: "fill", Selector: "input", EnvKey: "VULNETIC_CRED_1_PASSWORD"}, {Kind: "read"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPageExtractionIsTextOnlyAndBounded(t *testing.T) {
	u, _ := url.Parse("https://example.test/docs/")
	text, links := extractPage([]byte(`<html><body>Hello<script>SECRET_SCRIPT</script><input value="SECRET_INPUT"><style>SECRET_STYLE</style><a href="guide">Guide</a><a href="javascript:alert(1)">Bad link</a></body></html>`), u)
	if strings.Contains(text, "SECRET") || len(links) != 1 || links[0].URL != "https://example.test/docs/guide" {
		t.Fatalf("%q %+v", text, links)
	}
	text, _ = extractPage([]byte("<body>"+strings.Repeat("x", 100000)+"</body>"), u)
	if len(text) > 32000 {
		t.Fatal("page text cap exceeded")
	}
}

func TestProviderMetadataIsAHintNotACompatibilityClaim(t *testing.T) {
	value := ModelMetadata{ID: "fixture", ContextLength: 128000, MaxOutputTokens: 8000}.publicMetadata()
	if value["context_tokens"] != 128000 || value["runtime_tested"] != false {
		t.Fatal(value)
	}
	if (ModelMetadata{ContextLength: -1}).contextTokens() != 0 {
		t.Fatal("unknown model capacity invented")
	}
}
