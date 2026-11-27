package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/intercept"
	"github.com/sordado123/vulnetic/sshexec"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) wireTargetApprovals() {
	sshexec.AuthorizeTarget = func(ctx context.Context, accountID, executorID int64, host, port string, addresses []string) error {
		if accountID <= 0 {
			return fmt.Errorf("operation_not_permitted: account required")
		}
		pg := s.m.pg.ForAccount(accountID)
		raw, _, err := pg.GetSetting("managed_target_approvals")
		if err != nil {
			return fmt.Errorf("execution_policy_unavailable: target approval settings")
		}
		if raw != "" && raw != "true" && raw != "false" && raw != "1" && raw != "0" {
			return fmt.Errorf("execution_policy_unavailable: invalid target approval setting")
		}
		if raw != "true" && raw != "1" {
			return nil
		}
		ri := agent.RunInfoFrom(ctx)
		if ri.AccountID != accountID {
			return fmt.Errorf("operation_not_permitted: account context required")
		}
		scope := "configuration"
		convID := intercept.ConvIDFromContext(ctx)
		if ri.TaskID > 0 {
			if owner, err := pg.AccountIDForTask(ri.TaskID); err != nil || owner != accountID {
				return fmt.Errorf("operation_not_permitted: task scope")
			}
			scope = "task:" + strconv.FormatInt(ri.TaskID, 10)
		} else if convID > 0 {
			c, err := pg.GetConversation(convID)
			if err != nil || c == nil || c.AccountID != accountID {
				return fmt.Errorf("operation_not_permitted: conversation scope")
			}
			scope = "conversation:" + strconv.FormatInt(convID, 10)
		}
		canonical := make([]string, 0, len(addresses))
		seen := map[string]bool{}
		for _, value := range addresses {
			ip, err := netip.ParseAddr(value)
			if err != nil {
				return fmt.Errorf("execution_policy_unavailable: invalid resolved address")
			}
			value = ip.Unmap().String()
			if !seen[value] {
				canonical = append(canonical, value)
				seen[value] = true
			}
		}
		sort.Strings(canonical)
		rawIPs, _ := json.Marshal(canonical)
		addressHash := fmt.Sprintf("%x", sha256.Sum256(rawIPs))
		destination := net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
		var approved bool
		if err := pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM managed_target_approvals WHERE account_id=$1 AND scope=$2 AND executor_id=$3 AND destination=$4 AND addresses=$5::jsonb)`, accountID, scope, executorID, destination, string(rawIPs)).Scan(&approved); err != nil {
			return fmt.Errorf("execution_policy_unavailable: target approval lookup")
		}
		if approved {
			return nil
		}
		payload, _ := json.Marshal(map[string]any{"scope": scope, "executor_id": executorID, "destination": destination, "resolved_addresses": canonical, "note": "Approves this exact host, port and address set for this scope. DNS changes require approval again. Mandatory platform blocks still apply."})
		if !s.m.interceptor.ForAccount(accountID).HandleAsk(ctx, convID, intercept.Decision{Action: "ask", Message: "Approve managed connection to " + destination + " in " + scope}, "managed_target_connection", payload) {
			return fmt.Errorf("operation_not_permitted: managed destination not approved")
		}
		_, err = pg.Exec(`INSERT INTO managed_target_approvals(account_id,scope,executor_id,destination,addresses,addresses_hash) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT DO NOTHING`, accountID, scope, executorID, destination, string(rawIPs), addressHash)
		if err != nil {
			return fmt.Errorf("execution_policy_unavailable: cannot persist destination approval")
		}
		return nil
	}
}
