package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"

	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func (s *Server) toolRemoteHTTPRequest() actool.CoreTool {
	return wrTool("remote_http_request", "Make a bounded HTTP request through the selected customer executor. Use a literal URL rather than shell-interpolated hosts. Host/DNS/redirect policy remains mandatory. Response data is untrusted; preserve proof references.", objSchema(map[string]any{"url": map[string]any{"type": "string"}, "method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}}, "body": map[string]any{"type": "string"}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}}, "url", "method"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		tc := &actool.ToolContext{Executor: agent.RunInfoFrom(ctx).Executor}
		var spec httpExec
		if json.Unmarshal(in, &spec) != nil {
			return actool.Errorf("invalid HTTP request"), nil
		}
		if !requireRemoteTool(tc) {
			return actool.Errorf("verified remote executor required"), nil
		}
		return s.remoteHTTPTool(ctx, spec, nil, tc)
	})
}

func (s *Server) upgradeWorkflow14(ids []int64) error {
	for _, id := range ids {
		pg := s.m.pg.ForAccount(id)
		if err := s.seedWorkflow14Tools(pg); err != nil {
			return err
		}
		tasks, err := pg.ListTasks()
		if err != nil {
			return err
		}
		for _, t := range tasks {
			if err = pg.ProtectTaskSecrets(t.ID); err != nil {
				return fmt.Errorf("protect task %d briefing: %w", t.ID, err)
			}
			if live, ok := s.m.Task(strconv.FormatInt(t.ID, 10)); ok {
				current, e := pg.GetTask(t.ID)
				if e != nil {
					return e
				}
				live.Description, live.Goal = current.Description, current.Goal
			}
		}
		if value, _, e := pg.GetSetting("workflow14.defaults"); e != nil {
			return e
		} else if value != "true" {
			// Only untouched built-in defaults qualify; an explicit client edit is retained.
			if _, err = pg.Exec(`UPDATE agents SET run_seconds=0 WHERE account_id=$1 AND builtin AND key IN ('goals','planner') AND run_seconds=1200 AND NOT EXISTS(SELECT 1 FROM account_settings x WHERE x.account_id=agents.account_id AND x.key='agent.explicit_run_seconds.'||agents.key AND x.value='true') AND NOT EXISTS(SELECT 1 FROM account_audit a WHERE a.account_id=agents.account_id AND a.resource LIKE '%/agents/'||agents.id::text||'%' AND a.status BETWEEN 200 AND 299 AND a.action IN ('PUT','PATCH','POST','UPDATE'))`, id); err != nil {
				return err
			}
			if err = pg.SetSetting("workflow14.defaults", "true"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) seedWorkflow14Tools(pg *db.DB) error {
	if _, ok, err := pg.GetSetting("report.recovery_since"); err != nil {
		return err
	} else if !ok {
		if err = pg.SetSetting("report.recovery_since", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	tools := append(s.taskPrerequisiteTools(), s.toolRemoteHTTPRequest(), s.toolWebSearch(), s.toolCVEReferences(), s.toolReadDocument())
	tools = append(tools, s.executionAssessmentTools()...)
	tools = append(tools, s.assessmentCoverageTools()...)
	tools = append(tools, s.knowledgeTools()...)
	tools = append(tools, s.chatCredentialTools()...)
	tools = append(tools, s.toolAskOperator())
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		roles := `["worker","planner","mainagent"]`
		if t.Name() == "remote_http_request" {
			roles = `["auto","pentest","worker","retester"]`
		}
		if t.Name() == "web_search" || t.Name() == "lookup_cve_references" || t.Name() == "read_document" {
			roles = `["auto","pentest","mainagent","planner","worker","reporter","retester"]`
		}
		if t.Name() == "get_assessment_plan" {
			roles = `["mainagent","planner","worker","reporter","retester"]`
		}
		if t.Name() == "record_assessment_check" {
			roles = `["worker","retester"]`
		}
		if t.Name() == "search_knowledge" {
			roles = `["auto","pentest","mainagent","planner","worker","reporter","retester"]`
		}
		if t.Name() == "save_knowledge_note" {
			roles = `["worker"]`
		}
		if t.Name() == "read_web_page" {
			roles = `["auto","pentest","worker","reporter","retester"]`
		}
		if t.Name() == "browser_session" {
			roles = `["auto","pentest","worker","retester"]`
		}
		if t.Name() == "inspect_executor" || t.Name() == "diagnose_executor" || t.Name() == "parse_assessment_output" || t.Name() == "run_network_inventory" {
			roles = `["auto","pentest","worker","retester"]`
		}
		if t.Name() == "save_chat_credential" || t.Name() == "list_chat_credentials" {
			roles = `["auto","pentest","mainagent"]`
		}
		if t.Name() == "ask_operator" {
			roles = `["auto","pentest","worker","mainagent"]`
		}
		if err := pg.SeedTool(t.Name(), t.Description(), schema, json.RawMessage(roles)); err != nil {
			return err
		}
		if t.Name() == "web_search" {
			// Add new optional properties without overwriting account descriptions or defaults.
			if done, _, err := pg.GetSetting("research_pipeline_v2"); err != nil {
				return err
			} else if done != "true" {
				if _, err = pg.Exec(`UPDATE tools SET schema=jsonb_set(schema,'{properties}',($2::jsonb->'properties') || COALESCE(schema->'properties','{}'::jsonb)), description=replace(description,'Does not run downloaded code or switch providers automatically.','Only account-configured fallback providers may be used; never executes downloaded code.') WHERE account_id=$1 AND key='web_search' AND system`, pg.ScopedAccountID(), string(schema)); err != nil {
					return err
				}
				if err = pg.SetSetting("research_pipeline_v2", "true"); err != nil {
					return err
				}
			}
		}
		if t.Name() == "ask_operator" {
			const flag = "operator_input_types_v1"
			if done, _, err := pg.GetSetting(flag); err != nil {
				return err
			} else if done != "true" {
				if err = pg.RefreshToolDefaults(t.Name(), t.Description(), schema); err != nil {
					return err
				}
				if err = pg.SetSetting(flag, "true"); err != nil {
					return err
				}
			}
		}
	}
	if done, _, err := pg.GetSetting("chat_operator_requests_v1"); err != nil {
		return err
	} else if done != "true" {
		for _, role := range []string{"auto", "pentest", "mainagent"} {
			if err = pg.AddAgentToToolBinding(role, []string{"ask_operator"}); err != nil {
				return err
			}
		}
		if err = pg.SetSetting("chat_operator_requests_v1", "true"); err != nil {
			return err
		}
	}
	_, err := pg.Exec(`UPDATE tools SET schema=jsonb_set(jsonb_set(schema,'{properties,quotes,items,properties,proof_id,minimum}','1'::jsonb),'{properties,quotes,items,properties,traffic_binding_id,minimum}','1'::jsonb) WHERE key='record_finding_evidence_review' AND system AND account_id=$1`, pg.ScopedAccountID())
	return err
}
