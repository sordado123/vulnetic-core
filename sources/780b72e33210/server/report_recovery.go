package server

import (
	"fmt"
	"log"
	"strconv"

	"github.com/sordado123/vulnetic/db"
)

// Findings are the durable report queue. Recover only conversations that never ran tools.
func (sc *Scheduler) reconcileReports(triggers []*db.AgentTrigger) {
	enabled := false
	var account int64
	for _, tr := range triggers {
		if tr.AgentKey == "reporter" && tr.Enabled && tr.OnToolCall && containsFold(tr.ToolNames, "report_finding") {
			enabled = true
			account = tr.AccountID
		}
	}
	if !enabled {
		return
	}
	if account <= 0 {
		return
	}
	if a, err := sc.pg.GetAgentByKey("reporter"); err != nil || a == nil || !a.Enabled {
		return
	}
	since, ok, err := sc.pg.GetSetting("report.recovery_since")
	if err != nil || !ok {
		return
	}
	rows, err := sc.pg.Query(`SELECT f.id,f.node_id,t.id,t.description,t.goal,f.evidence_version FROM findings f JOIN tasks t ON t.id=f.task_id AND t.account_id=f.account_id WHERE f.account_id=$1 AND t.deleted_at IS NULL AND t.archived_at IS NULL AND NOT t.paused AND (t.status IN ('created','running') OR f.created_at >= $2::timestamptz) AND (coalesce(f.report,'')='' OR f.report_evidence_version<>f.evidence_version) ORDER BY CASE WHEN t.status='running' THEN 0 ELSE 1 END,f.id LIMIT 20`, account, since)
	if err != nil {
		log.Printf("[report] queue unavailable for account %d", account)
		return
	}
	type job struct {
		finding, node, task, version int64
		description, goal            string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.finding, &j.node, &j.task, &j.description, &j.goal, &j.version); err != nil {
			break
		}
		jobs = append(jobs, j)
	}
	if scanErr := rows.Err(); scanErr != nil {
		err = scanErr
	}
	rows.Close()
	if err != nil {
		return
	}
	for _, j := range jobs {
		key := fmt.Sprintf("%d:reporter", account)
		if _, busy := sc.s.reportJobs.LoadOrStore(key, true); busy {
			continue
		}
		setting := fmt.Sprintf("report.job.%d.%d", j.finding, j.version)
		value, _, readErr := sc.pg.GetSetting(setting)
		if readErr != nil {
			sc.s.reportJobs.Delete(key)
			continue
		}
		var conv *db.Conversation
		if id, _ := strconv.ParseInt(value, 10, 64); id > 0 {
			conv, err = sc.pg.GetConversation(id)
		} else {
			// Adopt old empty Reporter threads without deleting or duplicating their history.
			var id int64
			_ = sc.pg.QueryRow(`SELECT c.id FROM conversations c WHERE c.account_id=$1 AND c.source_task_id=$2 AND c.agent_key='reporter' AND NOT EXISTS(SELECT 1 FROM conversation_activities a WHERE a.conversation_id=c.id) AND NOT EXISTS(SELECT 1 FROM account_settings x WHERE x.account_id=c.account_id AND x.key LIKE 'report.job.%' AND x.value=c.id::text) ORDER BY c.id LIMIT 1`, account, j.task).Scan(&id)
			if id > 0 {
				conv, err = sc.pg.GetConversation(id)
			} else {
				conv, err = sc.pg.CreateConversation(account, "reporter", fmt.Sprintf("Report · finding#%d · task#%d", j.finding, j.task), nil)
			}
			if err == nil && conv != nil {
				err = sc.pg.BindTriggeredConversation(account, conv.ID, j.task)
			}
			if err == nil && conv != nil {
				err = sc.pg.SetSetting(setting, strconv.FormatInt(conv.ID, 10))
			}
		}
		if err != nil || conv == nil {
			sc.s.reportJobs.Delete(key)
			continue
		}
		var started bool
		if err = sc.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversation_activities WHERE conversation_id=$1 AND kind NOT IN ('user','checkpoint'))`, conv.ID).Scan(&started); err != nil || started {
			sc.s.reportJobs.Delete(key)
			continue
		}
		go func(j job, convID int64, key string) {
			defer sc.s.reportJobs.Delete(key)
			message := reporterToolCallMessage + fmt.Sprintf("\nPersisted finding_id=%d; finding_node_id=%d; task_id=%d. Read the recorded evidence. Do not execute checks or confirm findings.", j.finding, j.node, j.task)
			sc.s.runTriggeredRun(triggeredRun{accountID: account, agentKey: "reporter", conversationID: convID, taskID: j.task, message: message, taskDesc: j.description, taskGoal: j.goal})
		}(j, conv.ID, key)
	}
}
