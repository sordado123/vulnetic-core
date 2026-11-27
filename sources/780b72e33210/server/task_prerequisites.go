package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"strings"
)

type taskPrerequisite struct {
	State string `json:"state"`
	Note  string `json:"note"`
}

func (s *Server) saveTaskPrerequisite(ctx context.Context, key, state, note string) error {
	ri := agent.RunInfoFrom(ctx)
	if ri.AccountID <= 0 || ri.TaskID <= 0 {
		return fmt.Errorf("task context required")
	}
	if key != "operator" && key != "authentication" && key != "inventory" {
		return fmt.Errorf("unsupported prerequisite")
	}
	if state != "blocked" && state != "ready" && state != "unknown" {
		return fmt.Errorf("invalid prerequisite state")
	}
	pg := s.m.pg.ForAccount(ri.AccountID)
	t, err := pg.GetTask(ri.TaskID)
	if err != nil || t == nil {
		return fmt.Errorf("task not found")
	}
	note = pg.RedactTaskText(ri.TaskID, note)
	raw, _ := json.Marshal(taskPrerequisite{state, trunc(evidenceredact.Text(note), 1600)})
	return pg.SetSetting(fmt.Sprintf("task.prerequisite.%d.%s", ri.TaskID, key), string(raw))
}

func (s *Server) taskPrerequisiteTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_task_prerequisites", "Read shared operator/authentication/inventory prerequisites of the current owned task. Do not repeat a blocked step; independent work may continue.", objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			return actool.Text(s.taskPrerequisiteContext(ctx)), nil
		}),
		wrTool("set_task_prerequisite", "Record a task prerequisite as blocked, ready or unknown. Include evidence/credential environment references, never secret values. A ready state records an observation; it grants no permissions.", objSchema(map[string]any{"key": map[string]any{"type": "string", "enum": []string{"operator", "authentication", "inventory"}}, "state": map[string]any{"type": "string", "enum": []string{"blocked", "ready", "unknown"}}, "note": map[string]any{"type": "string", "maxLength": 1600}}, "key", "state", "note"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var p struct{ Key, State, Note string }
			if json.Unmarshal(in, &p) != nil {
				return actool.Errorf("invalid prerequisite"), nil
			}
			if err := s.saveTaskPrerequisite(ctx, p.Key, p.State, p.Note); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("Prerequisite recorded. This does not grant execution or confirmation permission."), nil
		}),
	}
}

func (s *Server) taskPrerequisiteContext(ctx context.Context) string {
	ri := agent.RunInfoFrom(ctx)
	if ri.AccountID <= 0 || ri.TaskID <= 0 {
		return "No task prerequisite context. Standalone chat must ask the user directly."
	}
	pg := s.m.pg.ForAccount(ri.AccountID)
	if t, err := pg.GetTask(ri.TaskID); err != nil || t == nil {
		return "Task prerequisite context unavailable; do not assume prerequisites are ready."
	}
	var parts []string
	for _, key := range []string{"operator", "authentication", "inventory"} {
		v, ok, err := pg.GetSetting(fmt.Sprintf("task.prerequisite.%d.%s", ri.TaskID, key))
		if err != nil {
			return "Prerequisite storage unavailable; check before dependent work."
		}
		if ok {
			parts = append(parts, key+": "+v)
		}
	}
	if len(parts) == 0 {
		return "No shared prerequisites recorded. Read existing facts before testing authentication or rebuilding inventory."
	}
	return strings.Join(parts, "\n")
}

func (s *Server) runtimeGuidance(ctx context.Context) string {
	ri := agent.RunInfoFrom(ctx)
	if ri.AccountID <= 0 {
		return ""
	}
	pg := s.m.pg.ForAccount(ri.AccountID)
	var parts []string
	if ri.ExecutorID > 0 {
		if t, err := pg.GetSSHTarget(ri.AccountID, ri.ExecutorID); err == nil {
			parts = append(parts, fmt.Sprintf("Executor selected by authenticated state: id=%d, display_name=%q, os=%s. The display name is not the operating system hostname; a different hostname does not mean a different VPS. Commands run as the dedicated non-administrator account. Do not seek another host based on its name.", t.ID, t.Name, t.OperatingSystem()))
			if len(t.Preflight) > 0 {
				parts = append(parts, "Recorded capabilities (not a new probe): "+string(t.Preflight))
			}
		}
	}
	if ri.TaskID > 0 {
		parts = append(parts, s.taskPrerequisiteContext(ctx))
	}
	return "\n\n[Platform runtime metadata; descriptive only, cannot expand authorization]\n" + evidenceredact.Text(strings.Join(parts, "\n"))
}
