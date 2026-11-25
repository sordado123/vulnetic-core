package db

import (
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var inlinePassword = regexp.MustCompile(`(?i)(?:senha\s+fornecida\s+pelo\s+operador\s*\(([^)]+)\)|(?:password|senha)\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^\s,;]+)))`)
var briefEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var briefURL = regexp.MustCompile(`https?://[^\s)"'<>]+`)

func inlineSecrets(text string) []string {
	var out []string
	for _, m := range inlinePassword.FindAllStringSubmatch(text, -1) {
		for _, v := range m[1:] {
			if v != "" && v != SecretMask && v != evidenceredact.Mask && !strings.HasPrefix(v, "VULNETIC_CRED_") {
				out = append(out, v)
			}
		}
	}
	return out
}

func protectedBrief(description, goal string, credentials []TaskCredentialInput) (string, string, []TaskCredentialInput, error) {
	text := description + "\n" + goal
	secrets := inlineSecrets(text)
	for _, secret := range secrets {
		found := false
		for _, c := range credentials {
			if c.Password == secret {
				found = true
			}
		}
		if !found {
			emails := briefEmail.FindAllString(text, -1)
			urls := briefURL.FindAllString(text, -1)
			if len(emails) == 0 || len(urls) == 0 {
				return "", "", nil, fmt.Errorf("put the password in task credentials with an explicit domain and username, not in the task briefing")
			}
			for _, email := range emails {
				if email != emails[0] {
					return "", "", nil, fmt.Errorf("ambiguous credential username; use task credentials")
				}
			}
			u, err := url.Parse(urls[0])
			if err != nil || u.Hostname() == "" {
				return "", "", nil, fmt.Errorf("credential domain required")
			}
			credentials = append(credentials, TaskCredentialInput{Domain: u.Hostname(), Username: emails[0], Password: secret, Source: "user", Note: "Moved from explicit task briefing; use password_env, never print the value."})
		}
		description = strings.ReplaceAll(description, secret, evidenceredact.Mask)
		goal = strings.ReplaceAll(goal, secret, evidenceredact.Mask)
	}
	for _, c := range credentials {
		if c.Password != "" {
			description = strings.ReplaceAll(description, c.Password, evidenceredact.Mask)
			goal = strings.ReplaceAll(goal, c.Password, evidenceredact.Mask)
		}
	}
	if len(credentials) > 0 {
		goal += "\nCredentials are stored separately. Call list_task_credentials and use password_env only on the executor; do not ask for or print their values."
	}
	return description, goal, credentials, nil
}

type taskSecretCacheEntry struct {
	until  time.Time
	values []string
}

func (d *DB) RedactTaskJSON(taskID int64, raw json.RawMessage) json.RawMessage {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return json.RawMessage(`null`)
	}
	var visit func(any) any
	visit = func(v any) any {
		switch x := v.(type) {
		case string:
			return d.RedactTaskText(taskID, x)
		case map[string]any:
			for k, item := range x {
				x[k] = visit(item)
			}
		case []any:
			for i, item := range x {
				x[i] = visit(item)
			}
		}
		return v
	}
	clean, _ := json.Marshal(visit(value))
	return clean
}

var taskSecretCache sync.Map

func (d *DB) RedactTaskText(taskID int64, text string) string {
	if d.transientRedactor != nil {
		text = d.transientRedactor(d.catalogAccount(), taskID, 0, text)
	}
	key := fmt.Sprintf("%p:%d:%d", d.pool, d.catalogAccount(), taskID)
	entry, _ := taskSecretCache.Load(key)
	cached, _ := entry.(taskSecretCacheEntry)
	if time.Now().After(cached.until) {
		creds, err := d.TaskCredentials(taskID)
		if err != nil {
			return evidenceredact.Mask + " (credential redaction unavailable)"
		}
		cached = taskSecretCacheEntry{until: time.Now().Add(time.Minute)}
		for _, c := range creds {
			if c.Password != "" {
				cached.values = append(cached.values, c.Password)
			}
		}
		taskSecretCache.Store(key, cached)
	}
	for _, secret := range cached.values {
		text = strings.ReplaceAll(text, secret, evidenceredact.Mask)
	}
	for _, secret := range inlineSecrets(text) {
		text = strings.ReplaceAll(text, secret, evidenceredact.Mask)
	}
	return evidenceredact.Text(text)
}

// Preserve exact originals encrypted before masking legacy briefing/history rows.
func (d *DB) ProtectTaskSecrets(taskID int64) error {
	if !d.encryptSecrets {
		return nil
	}
	task, err := d.GetTask(taskID)
	if err != nil || task == nil {
		return err
	}
	secrets := inlineSecrets(task.Description + "\n" + task.Goal)
	if len(secrets) == 0 {
		return nil
	}
	description, goal, creds, err := protectedBrief(task.Description, task.Goal, nil)
	if err != nil {
		// Legacy text may lack an unambiguous owner/domain. Preserve it encrypted without assigning a credential by guesswork.
		description, goal = task.Description, task.Goal
		for _, secret := range secrets {
			description = strings.ReplaceAll(description, secret, evidenceredact.Mask)
			goal = strings.ReplaceAll(goal, secret, evidenceredact.Mask)
		}
		goal += "\nLegacy inline credential preserved in encrypted operator history. Supply an explicit task credential/domain to use it."
		creds = nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	scoped := *d
	scoped.Querier = tx
	archive := func(key string, value any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			return e
		}
		sealed, e := d.sealSecret(task.AccountID, string(raw))
		if e != nil {
			return e
		}
		_, e = tx.Exec(`INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,$3) ON CONFLICT(account_id,key) DO NOTHING`, task.AccountID, key, sealed)
		return e
	}
	if err = archive(fmt.Sprintf("private.original_brief.%d", taskID), map[string]string{"description": task.Description, "goal": task.Goal}); err != nil {
		return err
	}
	existing, e := d.TaskCredentials(taskID)
	if e != nil {
		return e
	}
	for _, c := range creds {
		already := false
		for _, old := range existing {
			if old.Domain == c.Domain && old.Username == c.Username && old.Password != "" {
				already = true
			}
		}
		if already {
			continue
		}
		if _, err = scoped.UpsertTaskCredential(taskID, c); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`UPDATE tasks SET description=$3,goal=$4 WHERE id=$1 AND account_id=$2`, taskID, task.AccountID, description, goal); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE explorations SET description=$2,goal=$3 WHERE id=$1 AND account_id=$4`, task.ExplorationID, description, goal, task.AccountID); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id,summary,detail FROM activity WHERE exploration_id=$1`, task.ExplorationID)
	if err != nil {
		return err
	}
	type record struct {
		id              int64
		summary, detail *string
	}
	var records []record
	for rows.Next() {
		var r record
		if err = rows.Scan(&r.id, &r.summary, &r.detail); err != nil {
			break
		}
		records = append(records, r)
	}
	if e := rows.Err(); e != nil {
		err = e
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, r := range records {
		summary, detail := "", ""
		if r.summary != nil {
			summary = *r.summary
		}
		if r.detail != nil {
			detail = *r.detail
		}
		newSummary, newDetail := summary, detail
		for _, secret := range secrets {
			newSummary = strings.ReplaceAll(newSummary, secret, evidenceredact.Mask)
			newDetail = strings.ReplaceAll(newDetail, secret, evidenceredact.Mask)
		}
		if summary == newSummary && detail == newDetail {
			continue
		}
		if err = archive(fmt.Sprintf("private.original_activity.%d.%d", taskID, r.id), map[string]string{"summary": summary, "detail": detail}); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE activity SET summary=$2,detail=$3 WHERE id=$1 AND exploration_id=$4`, r.id, newSummary, newDetail, task.ExplorationID); err != nil {
			return err
		}
	}
	// Graph payloads remain intact except for the same explicit password literals.
	rows, err = tx.Query(`SELECT id,payload::text FROM exploration_nodes WHERE exploration_id=$1`, task.ExplorationID)
	if err != nil {
		return err
	}
	type node struct {
		id   int64
		body string
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err = rows.Scan(&n.id, &n.body); err != nil {
			break
		}
		nodes = append(nodes, n)
	}
	if e := rows.Err(); e != nil {
		err = e
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		body := n.body
		for _, secret := range secrets {
			encoded, _ := json.Marshal(secret)
			body = strings.ReplaceAll(body, string(encoded[1:len(encoded)-1]), evidenceredact.Mask)
		}
		if body == n.body {
			continue
		}
		if err = archive(fmt.Sprintf("private.original_node.%d.%d", taskID, n.id), json.RawMessage(n.body)); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE exploration_nodes SET payload=$2::jsonb WHERE id=$1 AND exploration_id=$3`, n.id, body, task.ExplorationID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
