package db

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TaskCredential is a per-task test account (#3): either declared by the user at
// task creation (source=user, e.g. a program-provided alias account) or registered
// by the agent itself and recorded so it is not forgotten (source=agent).
//
// Passwords are sealed at rest with the account's vault DEK (see sealSecret/
// openSecret); execution receives secrets through environment entries, while
// the model receives only their names. The UI masks the
// password by default behind an explicit reveal. Only dedicated test accounts
// belong here.
type TaskCredential struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Domain    string    `json:"domain"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Source    string    `json:"source"` // "user" | "agent"
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TaskCredentialInput validates and normalizes one upsert. Empty username or
// domain is rejected; an empty password is allowed only for source=user (the
// "agent generates and records it later" mode from #3).
type TaskCredentialInput struct {
	Domain   string
	Username string
	Password string
	Source   string
	Note     string
}

var ErrTaskCredentialInvalid = errors.New("credential domain and username are required")

func (in TaskCredentialInput) normalize() (TaskCredentialInput, error) {
	in.Domain = strings.TrimSpace(in.Domain)
	in.Username = strings.TrimSpace(in.Username)
	in.Password = strings.TrimSpace(in.Password)
	in.Note = strings.TrimSpace(in.Note)
	if in.Source != "agent" {
		in.Source = "user"
	}
	if in.Domain == "" || in.Username == "" {
		return in, ErrTaskCredentialInvalid
	}
	if in.Password == "" && in.Source == "agent" {
		return in, errors.New("agent-recorded credentials need the password that was set")
	}
	return in, nil
}

// UpsertTaskCredential inserts or updates the (task, domain, username) entry: an
// agent re-registering the same account overwrites the password in place instead
// of piling up a second row.
func (d *DB) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("task", taskID)
	}
	in, err := in.normalize()
	if err != nil {
		return TaskCredential{}, err
	}
	owner, err := d.AccountIDForTask(taskID)
	if err != nil {
		return TaskCredential{}, err
	}
	if in.Password == SecretMask {
		if err = d.QueryRow(`SELECT password FROM task_credentials WHERE task_id=$1 AND domain=$2 AND username=$3`, taskID, in.Domain, in.Username).Scan(&in.Password); err != nil {
			return TaskCredential{}, err
		}
		in.Password, err = d.openSecret(owner, in.Password)
		if err != nil {
			return TaskCredential{}, err
		}
	}
	storedPassword, err := d.sealSecret(owner, in.Password)
	if err != nil {
		return TaskCredential{}, err
	}
	var c TaskCredential
	err = d.QueryRow(`
		INSERT INTO task_credentials (task_id, domain, username, password, source, note)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (task_id, domain, username) DO UPDATE
		SET password = EXCLUDED.password,
		    source   = EXCLUDED.source,
		    note     = CASE WHEN EXCLUDED.note = '' THEN task_credentials.note ELSE EXCLUDED.note END,
		    updated_at = now()
		RETURNING id, task_id, domain, username, password, source, note, created_at, updated_at`,
		taskID, in.Domain, in.Username, storedPassword, in.Source, in.Note).
		Scan(&c.ID, &c.TaskID, &c.Domain, &c.Username, &c.Password, &c.Source, &c.Note, &c.CreatedAt, &c.UpdatedAt)
	if err == nil {
		c.Password, err = d.openSecret(owner, c.Password)
	}
	if err == nil {
		taskSecretCache.Delete(fmt.Sprintf("%p:%d:%d", d.pool, d.catalogAccount(), taskID))
	}
	return c, err
}

// TaskCredentials lists a task's credentials, oldest first (the user-declared
// ones keep their position ahead of agent-discovered ones).
func (d *DB) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("task", taskID)
	}
	owner, err := d.AccountIDForTask(taskID)
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`
		SELECT id, task_id, domain, username, password, source, note, created_at, updated_at
		FROM task_credentials WHERE task_id = $1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskCredential
	for rows.Next() {
		var c TaskCredential
		if err := rows.Scan(&c.ID, &c.TaskID, &c.Domain, &c.Username, &c.Password, &c.Source, &c.Note, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		plain, err := d.openSecret(owner, c.Password)
		if err != nil {
			return nil, err
		}
		c.Password = plain
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteTaskCredential removes one entry; taskID scopes the delete so a stale
// request cannot cross tasks.
func (d *DB) DeleteTaskCredential(taskID, id int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("task", taskID)
	}
	tag, err := d.Exec(`DELETE FROM task_credentials WHERE id = $1 AND task_id = $2`, id, taskID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return errors.New("credential not found")
	}
	return nil
}

// Thin wrappers on ExplorationStore: the ToolSet already holds the task's
// exploration store, so credential tools need no extra wiring.

func (s *ExplorationStore) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	return s.db.UpsertTaskCredential(taskID, in)
}

func (s *ExplorationStore) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	return s.db.TaskCredentials(taskID)
}

// Password values travel only as explicitly requested executor environment entries.
func CredentialPasswordEnv(id int64) string { return fmt.Sprintf("VULNETIC_CRED_%d_PASSWORD", id) }

var credentialEnvRE = regexp.MustCompile(`VULNETIC_CRED_(\d+)_PASSWORD`)

func CredentialEnvironment(command string, creds []TaskCredential) ([]string, error) {
	if strings.Contains(command, "{{cred:") {
		return nil, errors.New("legacy credential placeholders are disabled; list_task_credentials returns password_env; read the environment variable in the invoked program")
	}
	byID := map[string]string{}
	for _, c := range creds {
		byID[strconv.FormatInt(c.ID, 10)] = c.Password
	}
	env := []string{}
	seen := map[string]bool{}
	for _, match := range credentialEnvRE.FindAllStringSubmatch(command, -1) {
		if seen[match[0]] {
			continue
		}
		seen[match[0]] = true
		password, ok := byID[match[1]]
		if !ok || password == "" || strings.ContainsRune(password, 0) {
			return nil, errors.New("requested task credential is unavailable; command was not executed")
		}
		env = append(env, match[0]+"="+password)
	}
	return env, nil
}
