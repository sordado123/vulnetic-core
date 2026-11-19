package server

import (
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/traffic"
)

func (s *Server) seedAccountCatalog(pg *db.DB) error {
	if err := s.seedFindingReviewer(pg); err != nil {
		return err
	}
	if err := s.seedCVEVerificationTools(pg); err != nil {
		return err
	}
	if err := pg.SeedAccountAgents(agent.BuiltinPromptSeeds()); err != nil {
		return err
	}
	for _, seed := range agent.BuiltinToolSeeds() {
		schema, err := json.Marshal(seed.Schema)
		if err != nil {
			return err
		}
		bindings, _ := json.Marshal(seed.Agents)
		if err := pg.SeedTool(seed.Key, seed.Desc, schema, bindings); err != nil {
			return err
		}
	}
	for _, tool := range traffic.SeedToolMetas() {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := pg.SeedTool(tool.Name(), tool.Description(), schema, json.RawMessage(`["worker"]`)); err != nil {
			return err
		}
	}
	for _, tool := range append(s.orchestrationTools(), s.platformTools()...) {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := pg.SeedTool(tool.Name(), tool.Description(), schema, json.RawMessage(`["auto"]`)); err != nil {
			return err
		}
	}
	for _, seed := range []struct{ key, name, description, prompt string }{
		{"reporter", "Report writer", "Writes reports from recorded findings and execution evidence.", agent.ReporterDefaultPrompt},
		{db.FindingRetestAgentKey, "Vulnerability Retest", "Runs an independent retest while preserving the original evidence.", agent.RetesterDefaultPrompt},
	} {
		if err := pg.SeedCustomAgent(seed.key, seed.name, seed.description, seed.prompt); err != nil {
			return err
		}
	}
	for _, tool := range s.findingRetestTools() {
		schema, err := json.Marshal(tool.InputSchema())
		if err != nil {
			return err
		}
		if err = pg.SeedTool(tool.Name(), tool.Description(), schema, json.RawMessage(`["retester"]`)); err != nil {
			return err
		}
	}
	if err := pg.AddAgentToToolBinding("retester", []string{"Bash", "lookup_cve"}); err != nil {
		return err
	}
	if err := pg.AddAgentToToolBinding("reporter", []string{"update_finding_report", "get_task_node_detail", "list_task_findings", "get_task_worker_trace", "list_task_worker_traces", "search_task_worker_traces", "get_task_graph", "get_finding_traffic"}); err != nil {
		return err
	}
	if err := pg.SetAgentTriggerBehavior("reporter", "serial", "none", 1); err != nil {
		return err
	}
	_, err := pg.CreateTrigger(&db.AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"report_finding"}, ToolCallMessage: reporterToolCallMessage})
	if err != nil {
		return err
	}
	if err := s.seedWorkflow14Tools(pg); err != nil {
		return err
	}
	if err := ensureAgentToolProfiles(pg); err != nil {
		return err
	}
	if err := s.seedChatProofTools(pg); err != nil {
		return err
	}
	if err := s.seedAttackChainTool(pg); err != nil {
		return err
	}
	return pg.SetSetting("catalog_seed_v1", "true")
}

// Add only the new discovery tool; preserve existing prompts, switches and bindings.
func (s *Server) seedVPSDiscovery() error {
	rows, err := s.m.pg.Query(`SELECT id FROM accounts ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if err = s.upgradeWorkflow14(ids); err != nil {
		return err
	}
	tool := s.toolListVPS()
	schema, _ := json.Marshal(tool.InputSchema())
	for _, id := range ids {
		if err = s.seedFindingReviewer(s.m.pg.ForAccount(id)); err != nil {
			return err
		}
		if err = s.seedCVEVerificationTools(s.m.pg.ForAccount(id)); err != nil {
			return err
		}
		if err = s.m.pg.ForAccount(id).SeedTool(tool.Name(), tool.Description(), schema, json.RawMessage(`["auto"]`)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) seedAttackChainTool(pg *db.DB) error {
	for _, seed := range agent.BuiltinToolSeeds() {
		if seed.Key != "record_attack_chain" {
			continue
		}
		schema, err := json.Marshal(seed.Schema)
		if err != nil {
			return err
		}
		bindings, err := json.Marshal(seed.Agents)
		if err != nil {
			return err
		}
		if err = pg.SeedTool(seed.Key, seed.Desc, schema, bindings); err != nil {
			return err
		}
		return pg.EnableAttackChainPlanner()
	}
	return fmt.Errorf("attack chain tool is unavailable")
}

func (s *Server) seedFindingReviewer(pg *db.DB) error {
	if value, _, err := pg.GetSetting("finding_reviewer_v1"); err != nil {
		return err
	} else if value == "true" {
		return nil
	}
	if err := pg.SeedCustomAgent(findingReviewerKey, "Evidence reviewer", "Advisory independent evidence review; human confirmation remains mandatory.", findingReviewerPrompt); err != nil {
		return err
	}
	for _, tool := range s.findingEvidenceTools() {
		schema, err := json.Marshal(tool.InputSchema())
		if err != nil {
			return err
		}
		if err = pg.SeedTool(tool.Name(), tool.Description(), schema, json.RawMessage(`["finding_reviewer","worker","reporter"]`)); err != nil {
			return err
		}
	}
	return pg.SetSetting("finding_reviewer_v1", "true")
}
