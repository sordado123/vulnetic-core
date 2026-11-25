package server

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/assessment"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/sshexec"
)

func (s *Server) toolNetworkInventory() actool.CoreTool {
	return wrTool("run_network_inventory", "Inventory explicit TCP ports on one approved host using Nmap on the selected executor. Uses connect scans without root, a DNS-pinned IP and XML parsing. Observed services/version claims are not verified vulnerabilities. No scripts, arbitrary flags, ranges or automatic installation.", objSchema(map[string]any{"host": map[string]any{"type": "string", "maxLength": 253}, "ports": map[string]any{"type": "array", "minItems": 1, "maxItems": 16, "items": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}}}, "host", "ports"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		ri := agent.RunInfoFrom(ctx)
		ex, ok := ri.Executor.(*sshexec.LazyExecutor)
		if !ok || ex == nil || ri.AccountID <= 0 || ex.AccountID != ri.AccountID {
			return actool.Errorf("authenticated customer executor required"), nil
		}
		var args struct {
			Host  string `json:"host"`
			Ports []int  `json:"ports"`
		}
		if json.Unmarshal(in, &args) != nil || len(args.Ports) < 1 || len(args.Ports) > 16 {
			return actool.Errorf("provide one host and 1–16 explicit TCP ports"), nil
		}
		if strings.ContainsAny(args.Host, "/\\@?#\x00\r\n ") {
			return actool.Errorf("host must be a hostname or IP, without URL or port"), nil
		}
		host, err := platformpolicy.Host(args.Host)
		if err != nil || host == "" {
			return actool.Errorf("invalid host"), nil
		}
		seen := map[int]bool{}
		var ports []string
		ip := ""
		for _, port := range args.Ports {
			if port < 1 || port > 65535 || seen[port] {
				return actool.Errorf("ports must be unique and between 1 and 65535"), nil
			}
			seen[port] = true
			addresses, err := ex.ResolveAuthorizedDestination(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return actool.Errorf("target resolution or authorization failed: " + actool.ResearchErrorCode(err)), nil
			}
			current, _, err := net.SplitHostPort(addresses[0])
			if err != nil {
				return actool.Errorf("invalid resolved destination"), nil
			}
			if ip != "" && current != ip {
				return actool.Errorf("DNS changed during authorization; retry inventory"), nil
			}
			ip = current
			ports = append(ports, strconv.Itoa(port))
		}
		sort.Strings(ports)
		program := "nmap"
		prefix := ""
		if ex.ExecutionOS() == "windows" {
			program = "nmap.exe"
			prefix = "& "
		}
		command := prefix + program + " -sT -sV --version-light -n -Pn --max-retries 1 --host-timeout 120s -p " + strings.Join(ports, ",") + " -oX - " + ex.Quote(ip)
		if strings.Contains(ip, ":") {
			command += " -6"
		}
		raw, _ := json.Marshal(map[string]any{"command": command, "timeout_ms": 135000})
		result, err := actool.NewBash().Call(ctx, raw, &actool.ToolContext{Executor: ex, PreserveOutput: true, MaxOutputChars: assessment.MaxOutput})
		if err != nil || result.IsError {
			return result, err
		}
		observations, err := assessment.Parse("nmap", []byte(result.Flatten()))
		if err != nil {
			return actool.Errorf("Nmap output was not complete XML; inspect the executor installation and capture its raw output using Bash"), nil
		}
		return jsonResult(map[string]any{"scanner": "nmap", "requested_host": host, "pinned_ip": ip, "ports": args.Ports, "observations": observations, "raw_xml": result.Flatten(), "untrusted": true, "verified": false})
	})
}
