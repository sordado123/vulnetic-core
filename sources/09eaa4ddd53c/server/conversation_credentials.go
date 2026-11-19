package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
)

func (s *Server) conversationCredentialResolver(accountID, convID int64) func(string) ([]string, error) {
	return func(command string) ([]string, error) {
		if !strings.Contains(command, "VULNETIC_CRED_") && !strings.Contains(command, "{{cred:") {
			return nil, nil
		}
		list, err := s.m.pg.ForAccount(accountID).ConversationCredentials(convID)
		if err != nil {
			return nil, fmt.Errorf("chat credentials unavailable; command was not executed")
		}
		return db.CredentialEnvironment(command, list)
	}
}

func (s *Server) chatCredentialTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("save_chat_credential", "Save a user-supplied or newly registered target account for this conversation before using it. Uses the source task's vault when this chat belongs to a task; otherwise this chat's account vault. Returns password_env, which is injected only into commands that name it. Never save platform or another account's secrets.", objSchema(map[string]any{"domain": map[string]any{"type": "string", "maxLength": 2048}, "username": map[string]any{"type": "string", "maxLength": 512}, "password": map[string]any{"type": "string", "maxLength": 4096}}, "domain", "username", "password"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			id, accountID := intercept.ConvIDFromContext(ctx), agent.RunInfoFrom(ctx).AccountID
			if id <= 0 || accountID <= 0 {
				return actool.Errorf("authenticated conversation required"), nil
			}
			var in struct {
				Domain   string `json:"domain"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if json.Unmarshal(raw, &in) != nil || len(in.Domain) > 2048 || len(in.Username) > 512 || len(in.Password) > 4096 {
				return actool.Errorf("invalid credential"), nil
			}
			c, err := s.m.pg.ForAccount(accountID).UpsertConversationCredential(ctx, id, db.TaskCredentialInput{Domain: in.Domain, Username: in.Username, Password: in.Password, Source: "agent"})
			if err != nil {
				return actool.Errorf("credential could not be saved; check its domain, username and the account vault"), nil
			}
			return jsonResult(map[string]any{"id": c.ID, "domain": c.Domain, "username": c.Username, "password_env": db.CredentialPasswordEnv(c.ID), "usage": "Read password_env in the invoked program on your executor. The value is not printed or substituted into command source."})
		}),
		wrTool("list_chat_credentials", "List the accounts saved for this conversation or its source task. Passwords remain usable through the returned password_env in Bash/Python/PowerShell commands on the selected executor. Do not probe platform environment variables or print secrets.", objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			id, accountID := intercept.ConvIDFromContext(ctx), agent.RunInfoFrom(ctx).AccountID
			if id <= 0 || accountID <= 0 {
				return actool.Errorf("authenticated conversation required"), nil
			}
			list, err := s.m.pg.ForAccount(accountID).ConversationCredentials(id)
			if err != nil {
				return actool.Errorf("chat credentials unavailable"), nil
			}
			out := []map[string]any{}
			for _, c := range list {
				out = append(out, map[string]any{"id": c.ID, "domain": c.Domain, "username": c.Username, "password_env": db.CredentialPasswordEnv(c.ID), "has_password": c.Password != ""})
			}
			return jsonResult(map[string]any{"credentials": out, "usage": "Only variables explicitly named in a command are injected. Read them in the invoked program, e.g. os.environ in Python or $env:NAME in PowerShell. They are not persistent global variables."})
		}),
	}
}
