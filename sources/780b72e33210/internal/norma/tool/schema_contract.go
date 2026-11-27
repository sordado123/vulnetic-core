package tool

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/sordado123/vulnetic/internal/norma/llm"
)

var functionName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ValidateToolContracts checks the exact model-facing schemas, without a model call.
func ValidateToolContracts(schemas []llm.ToolSchema) error {
	seen := map[string]bool{}
	for _, schema := range schemas {
		if !functionName.MatchString(schema.Name) || seen[schema.Name] {
			return fmt.Errorf("tool_contract_invalid: invalid or duplicate function name %q", schema.Name)
		}
		seen[schema.Name] = true
		raw, err := json.Marshal(schema.InputSchema)
		if err != nil {
			return fmt.Errorf("tool_contract_invalid: %s schema is not JSON", schema.Name)
		}
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil || object == nil || object["type"] != "object" {
			return fmt.Errorf("tool_contract_invalid: %s parameters must be an object schema", schema.Name)
		}
		if err := validateSchemaNode(object, 0); err != nil {
			return fmt.Errorf("tool_contract_invalid: %s: %w", schema.Name, err)
		}
	}
	return nil
}

func validateSchemaNode(node map[string]any, depth int) error {
	if depth > 32 {
		return fmt.Errorf("schema nesting exceeds 32")
	}
	if typ, ok := node["type"].(string); ok && typ != "object" && typ != "string" && typ != "number" && typ != "integer" && typ != "boolean" && typ != "array" && typ != "null" {
		return fmt.Errorf("unsupported schema type")
	}
	if value, present := node["properties"]; present {
		props, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("properties must be an object")
		}
		for _, value := range props {
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("property schema must be an object")
			}
			if err := validateSchemaNode(child, depth+1); err != nil {
				return err
			}
		}
	}
	if value, present := node["required"]; present {
		required, ok := value.([]any)
		if !ok {
			return fmt.Errorf("required must be an array")
		}
		props, _ := node["properties"].(map[string]any)
		for _, value := range required {
			key, ok := value.(string)
			if !ok || props[key] == nil {
				return fmt.Errorf("required property is not defined")
			}
		}
	}
	if node["type"] == "array" {
		child, ok := node["items"].(map[string]any)
		if !ok {
			return fmt.Errorf("array needs an items schema")
		}
		if err := validateSchemaNode(child, depth+1); err != nil {
			return err
		}
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		if value, present := node[key]; present {
			children, ok := value.([]any)
			if !ok || len(children) == 0 {
				return fmt.Errorf("invalid schema composition")
			}
			for _, value := range children {
				child, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("invalid schema branch")
				}
				if err := validateSchemaNode(child, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
