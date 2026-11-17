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
	case "create_tool", "update_tool", "create_custom_tool", "update_custom_tool", "update_skill_file", "create_skill", "update_skill", "create_mcp", "update_mcp", "create_agent", "update_agent", "upsert_asset", "register_finding", "report_finding", "update_finding_report", "record_finding", "record_execution_proof", "ask_operator":
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
