package agent

import (
	"slices"
	"testing"
)

func TestWorkflowRoleDefaults(t *testing.T) {
	profiles := DefaultToolProfiles()
	if !slices.Contains(profiles["planner"], "record_attack_chain") || slices.Contains(profiles["pentest"], "record_attack_chain") {
		t.Fatal("chain declarations must have a task-backed planner")
	}
	found := false
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key == "record_attack_chain" {
			found = slices.Contains(seed.Agents, "planner")
		}
	}
	if !found {
		t.Fatal("attack chain planner binding missing from persisted seed")
	}
	for _, role := range []string{"auto", "pentest", "mainagent", "goals", "planner", "reporter"} {
		for _, denied := range []string{"Bash", "kill_work", "goal_met", "record_finding_retest_result"} {
			if slices.Contains(profiles[role], denied) && !(denied == "Bash" && (role == "auto" || role == "pentest")) {
				t.Errorf("%s unexpectedly defaults to %s", role, denied)
			}
		}
		if roleWorkflowGuidance(role) == "" {
			t.Errorf("missing workflow for %s", role)
		}
	}
	for _, role := range []string{"auto", "pentest"} {
		for _, required := range []string{"Bash", "sleep", "list_conversation_proofs", "link_conversation_proofs"} {
			if !slices.Contains(profiles[role], required) {
				t.Errorf("%s missing %s", role, required)
			}
		}
	}
	for _, required := range []string{"Bash", "report_finding", "record_fact", "ask_operator"} {
		if !slices.Contains(profiles["worker"], required) {
			t.Errorf("worker missing %s", required)
		}
	}
	if !slices.Contains(profiles["reporter"], "update_finding_report") || !slices.Contains(profiles["planner"], "prove_goal") {
		t.Fatal("missing evidence handoff tools")
	}
	if !slices.Contains(profiles["pentest"], "spawn_task") {
		t.Fatal("standalone pentest must delegate into a task")
	}
}
