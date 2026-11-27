package platformpolicy

import (
	"encoding/json"
	"errors"
)

// Configuration and recorded observations remain editable; execution is checked separately.
func CheckTool(name string, input json.RawMessage) error {
	if err := Validate(); err != nil {
		return err
	}
	if LocalTool(name) {
		return errors.New("policy_denied: local tools are disabled in SaaS")
	}
	switch name {
	case "remote_http_request", "read_web_page", "browser_session":
		var a struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(input, &a) != nil || a.URL == "" {
			return errors.New("policy_denied: literal request URL required")
		}
		return CheckHost(a.URL)
	case "get_task_prerequisites", "set_task_prerequisite":
		return nil
	case "context_status", "compress_context", "search_context", "restore_context":
		return nil // Current-session records only; no network/execution capability or policy mutation.
	case "record_assessment_check", "get_assessment_plan", "save_knowledge_note", "search_knowledge", "parse_assessment_output":
		return nil // Owned observations; handlers enforce provenance and scope.
	case "steer_work", "add_task_hint", "add_hint", "get_worker_trace", "search_all_worker_traces", "search_task_worker_traces", "record_finding_evidence_review":
		// These handlers only coordinate or inspect owned records; their prose is not a network destination.
		return nil
	case "create_tool", "update_tool", "create_custom_tool", "update_custom_tool", "update_skill_file", "create_skill", "update_skill", "create_mcp", "update_mcp", "create_agent", "update_agent", "upsert_asset", "register_finding", "report_finding", "update_finding_report", "record_finding", "record_execution_proof", "record_fact", "ask_operator":
		return nil
	}
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return errors.New("policy_denied: invalid tool arguments")
	}
	var visit func(any) error
	visit = func(v any) error {
		switch x := v.(type) {
		case string:
			return CheckText(x)
		case []any:
			for _, child := range x {
				if err := visit(child); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, child := range x {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(value)
}
