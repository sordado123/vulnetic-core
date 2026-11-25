package server

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/agent"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/sshexec"
)

//go:embed browser_session.py
var browserSessionScript string

type browserAction struct {
	Kind     string `json:"kind"`
	Selector string `json:"selector,omitempty"`
	Value    string `json:"value,omitempty"`
	EnvKey   string `json:"env_key,omitempty"`
}

var browserCredential = regexp.MustCompile(`^(VULNETIC_CRED_[1-9][0-9]*_PASSWORD|VULNETIC_INPUT_[a-f0-9]{32}_VALUE)$`)

func validateBrowserActions(actions []browserAction) error {
	if len(actions) < 1 || len(actions) > 12 {
		return fmt.Errorf("provide 1–12 browser actions")
	}
	for _, a := range actions {
		if a.Kind != "fill" && a.Kind != "click" && a.Kind != "read" && a.Kind != "screenshot" {
			return fmt.Errorf("unsupported browser action")
		}
		if (a.Kind == "fill" || a.Kind == "click") && (a.Selector == "" || len(a.Selector) > 500) {
			return fmt.Errorf("bounded selector required")
		}
		if len(a.Value) > 4000 || (a.EnvKey != "" && !browserCredential.MatchString(a.EnvKey)) || (a.EnvKey != "" && a.Value != "") {
			return fmt.Errorf("invalid browser input reference")
		}
	}
	return nil
}

func (s *Server) toolBrowserSession() actool.CoreTool {
	return wrTool("browser_session", "Use an isolated Chromium session on the selected executor for bounded same-origin authenticated workflows. Requires Playwright/Chromium already installed there; never installs or disables the sandbox. Supports fill/click/read/screenshot; passwords and OTPs use the scoped environment reference supplied by credential/ask_operator tools. No arbitrary JavaScript, shell, cross-origin navigation, downloads or WebSockets. State and screenshots stay on the executor. Session validity is at most 30 minutes and within the original executor lease; neither deadline is renewed. Stop on MFA blockers and ask_operator; resume within the original browser deadline.", objSchema(map[string]any{
		"url":     map[string]any{"type": "string", "maxLength": 4096},
		"actions": map[string]any{"type": "array", "minItems": 1, "maxItems": 12, "items": map[string]any{"type": "object", "properties": map[string]any{"kind": map[string]any{"type": "string", "enum": []string{"fill", "click", "read", "screenshot"}}, "selector": map[string]any{"type": "string", "maxLength": 500}, "value": map[string]any{"type": "string", "maxLength": 4000}, "env_key": map[string]any{"type": "string", "maxLength": 100}}, "required": []string{"kind"}}},
	}, "url", "actions"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		ri := agent.RunInfoFrom(ctx)
		ex, ok := ri.Executor.(*sshexec.LazyExecutor)
		if !ok || ex == nil || ri.AccountID <= 0 || ex.AccountID != ri.AccountID {
			return actool.Errorf("authenticated customer executor required"), nil
		}
		var args struct {
			URL     string          `json:"url"`
			Actions []browserAction `json:"actions"`
		}
		if len(in) > 60000 || json.Unmarshal(in, &args) != nil {
			return actool.Errorf("invalid browser request"), nil
		}
		if err := validateBrowserActions(args.Actions); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		u, err := url.Parse(args.URL)
		if err != nil || u.User != nil || u.Hostname() == "" || len(args.URL) > 4096 || (u.Scheme != "http" && u.Scheme != "https") {
			return actool.Errorf("provide a literal HTTP(S) origin without embedded credentials"), nil
		}
		host, err := platformpolicy.Host(u.Hostname())
		if err != nil {
			return actool.Errorf("invalid browser host"), nil
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return actool.Errorf("invalid browser destination port"), nil
		}
		port = strconv.Itoa(portNumber)
		addresses, err := ex.ResolveAuthorizedDestination(ctx, net.JoinHostPort(host, port))
		if err != nil {
			return actool.Errorf("browser destination blocked or unavailable: " + actool.ResearchErrorCode(err)), nil
		}
		ip, _, err := net.SplitHostPort(addresses[0])
		if err != nil {
			return actool.Errorf("browser destination unavailable"), nil
		}
		if parsed, e := netip.ParseAddr(ip); e != nil || !parsed.Is4() {
			return actool.Errorf("managed browser currently requires an IPv4 destination; use read_web_page for IPv6"), nil
		}
		target, err := s.verifiedTarget(ri.AccountID, ex.TargetID)
		if err != nil || target.AgentExpiresAt == nil {
			return actool.Errorf("current expiring executor authorization required"), nil
		}
		deadline := *target.AgentExpiresAt
		ctx, cancel := context.WithDeadline(ctx, minTime(time.Now().Add(90*time.Second), deadline))
		defer cancel()
		u.Host = net.JoinHostPort(host, port)
		scope := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s:%d:%s://%s", ri.AccountID, ri.TaskID, ri.SessionID, ri.IntentID, u.Scheme, u.Host)))
		params := map[string]any{"url": u.String(), "actions": args.Actions, "pinned_ip": ip, "deadline": deadline.Unix(), "scope": hex.EncodeToString(scope[:16])}
		result, err := remotePython(ctx, browserSessionScript, params, 90000, &actool.ToolContext{Executor: ex})
		if err == nil && !result.IsError {
			var out struct {
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(result.Flatten())), &out) != nil {
				return actool.Errorf("browser returned an invalid response"), nil
			}
			result.IsError = out.Error != ""
		}
		return result, err
	})
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
