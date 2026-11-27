package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func conversationCredentialKey(id int64) string {
	return fmt.Sprintf("conversation.credentials.%d", id)
}

func (d *DB) ConversationCredentials(id int64) ([]TaskCredential, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return nil, sql.ErrNoRows
	}
	c, err := d.GetConversation(id)
	if err != nil || c == nil {
		return nil, sql.ErrNoRows
	}
	if c.SourceTaskID != nil {
		return d.TaskCredentials(*c.SourceTaskID)
	}
	value, found, err := d.GetSetting(conversationCredentialKey(id))
	if err != nil || !found {
		return []TaskCredential{}, err
	}
	raw, err := d.openJSON(d.accountID, json.RawMessage(value))
	if err != nil {
		return nil, err
	}
	var list []TaskCredential
	if json.Unmarshal(raw, &list) != nil {
		return nil, errors.New("conversation credential storage unavailable")
	}
	return list, nil
}

func (d *DB) UpsertConversationCredential(ctx context.Context, id int64, in TaskCredentialInput) (TaskCredential, error) {
	if !d.hasAccount || d.accountID <= 0 {
		return TaskCredential{}, sql.ErrNoRows
	}
	c, err := d.GetConversation(id)
	if err != nil || c == nil {
		return TaskCredential{}, sql.ErrNoRows
	}
	if c.SourceTaskID != nil {
		return d.UpsertTaskCredential(*c.SourceTaskID, in)
	}
	in, err = in.normalize()
	if err != nil {
		return TaskCredential{}, err
	}
	if len(in.Domain) > 2048 || len(in.Username) > 512 || len(in.Password) > 4096 || strings.ContainsRune(in.Password, 0) {
		return TaskCredential{}, errors.New("invalid credential")
	}
	if !d.encryptSecrets {
		return TaskCredential{}, errors.New("credential vault unavailable")
	}
	tx, nested := d.Querier.(*sql.Tx)
	if !nested {
		tx, err = d.BeginTx(ctx, nil)
		if err != nil {
			return TaskCredential{}, err
		}
		defer tx.Rollback()
	}
	scoped := *d
	scoped.Querier = tx
	key := conversationCredentialKey(id)
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_settings(account_id,key,value) VALUES($1,$2,'[]') ON CONFLICT DO NOTHING`, d.accountID, key); err != nil {
		return TaskCredential{}, err
	}
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT value FROM account_settings WHERE account_id=$1 AND key=$2 FOR UPDATE`, d.accountID, key).Scan(&locked); err != nil {
		return TaskCredential{}, err
	}
	list, err := scoped.ConversationCredentials(id)
	if err != nil {
		return TaskCredential{}, err
	}
	index := len(list)
	for i, old := range list {
		if old.Domain == in.Domain && old.Username == in.Username {
			index = i
			break
		}
	}
	if index == len(list) {
		if len(list) >= 100 {
			return TaskCredential{}, errors.New("conversation credential limit reached")
		}
		list = append(list, TaskCredential{ID: int64(index + 1)})
	}
	if in.Password == SecretMask {
		in.Password = list[index].Password
	}
	list[index].Domain, list[index].Username, list[index].Password, list[index].Source, list[index].Note = in.Domain, in.Username, in.Password, in.Source, in.Note
	raw, err := json.Marshal(list)
	if err != nil {
		return TaskCredential{}, err
	}
	sealed, err := scoped.sealJSON(d.accountID, raw)
	if err != nil {
		return TaskCredential{}, err
	}
	if err = scoped.SetSetting(key, string(sealed)); err != nil {
		return TaskCredential{}, err
	}
	if !nested {
		err = tx.Commit()
	}
	return list[index], err
}

// Capture only one explicit, unambiguous user-supplied account; never guess from target output.
func captureCredentialText(text, tool string, save func(TaskCredentialInput) (TaskCredential, error)) (string, error) {
	secrets := inlineSecrets(text)
	emails := briefEmail.FindAllString(text, -1)
	urls := briefURL.FindAllString(text, -1)
	if len(secrets) != 1 || len(emails) == 0 || len(urls) == 0 {
		return text, nil
	}
	if strings.Contains(text, "```") || strings.Contains(secrets[0], "VULNETIC_CRED_") || strings.Contains(secrets[0], "os.environ") || strings.Contains(secrets[0], "$env:") {
		return text, nil
	}
	for _, email := range emails {
		if email != emails[0] {
			return text, nil
		}
	}
	host := ""
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return text, nil
		}
		if host != "" && host != u.Hostname() {
			return text, nil
		}
		host = u.Hostname()
	}
	c, err := save(TaskCredentialInput{Domain: host, Username: emails[0], Password: secrets[0], Source: "user", Note: "Supplied explicitly by the user in chat; read password_env on the executor."})
	if err != nil {
		return "", err
	}
	return inlinePassword.ReplaceAllString(text, "credential_ref: "+CredentialPasswordEnv(c.ID)) + "\n[Credential saved. Call " + tool + " and read password_env in your executor command.]", nil
}

func (d *DB) CaptureConversationCredentialText(ctx context.Context, id int64, text string) (string, error) {
	return captureCredentialText(text, "list_chat_credentials", func(in TaskCredentialInput) (TaskCredential, error) {
		return d.UpsertConversationCredential(ctx, id, in)
	})
}
func (d *DB) CaptureTaskCredentialText(id int64, text string) (string, error) {
	return captureCredentialText(text, "list_task_credentials", func(in TaskCredentialInput) (TaskCredential, error) { return d.UpsertTaskCredential(id, in) })
}
