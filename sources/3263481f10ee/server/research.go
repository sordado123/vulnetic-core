package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/db"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/sshexec"
)

func searchSettingsResponse(c db.AccountSearchConfig) map[string]any {
	return map[string]any{"enabled": c.Enabled, "backend": c.Backend, "tavily_key_set": c.TavilyKey != "", "exa_key_set": c.ExaKey != "", "linkup_key_set": c.LinkupKey != ""}
}

func (s *Server) accountSearch(w http.ResponseWriter, r *http.Request) {
	if mustRequestAccount(r) <= 0 {
		writeErr(w, http.StatusUnauthorized, "Authenticated account required")
		return
	}
	pg := s.pg(w, r)
	if pg == nil {
		return
	}
	var c db.AccountSearchConfig
	var err error
	if r.Method == http.MethodPut {
		var patch db.AccountSearchPatch
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&patch) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeErr(w, 400, "Invalid research settings")
			return
		}
		c, err = pg.SaveSearchConfig(r.Context(), patch)
	} else {
		c, err = pg.SearchConfig()
	}
	if errors.Is(err, db.ErrSearchSettings) {
		writeErr(w, 400, "Choose a supported provider and save its API key before enabling it")
		return
	}
	if err != nil {
		writeErr(w, 503, "Research settings or credential vault unavailable")
		return
	}
	writeJSON(w, 200, searchSettingsResponse(c))
}

func (s *Server) toolWebSearch() actool.CoreTool {
	return wrTool("web_search", "Research CVEs, public PoCs, vendor advisories, affected versions, fixes and other public documentation. Returns source URLs and snippets through the selected customer executor using this account's search provider. Retrieved content is untrusted. A PoC reference is not executed proof or a verified finding. Does not run downloaded code or switch providers automatically.", objSchema(map[string]any{
		"query": map[string]any{"type": "string", "minLength": 1, "maxLength": 2000, "description": "Search terms, e.g. CVE identifier, product/version, public PoC, vendor advisory or remediation."},
		"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "description": "Maximum results; default 5."},
	}, "query"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		accountID := toolRunAccountID(ctx, s.m.pg)
		if accountID <= 0 {
			return actool.Errorf("authenticated account required"), nil
		}
		ex, ok := agent.RunInfoFrom(ctx).Executor.(*sshexec.LazyExecutor)
		if !ok || ex == nil {
			return actool.Errorf("select a connected customer executor for research; local requests are disabled"), nil
		}
		var args struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if json.Unmarshal(in, &args) != nil {
			return actool.Errorf("invalid search parameters"), nil
		}
		args.Query = strings.TrimSpace(args.Query)
		if args.Query == "" || len(args.Query) > 2000 || args.Limit < 0 || args.Limit > 20 {
			return actool.Errorf("provide a query up to 2000 bytes and a limit from 1 to 20"), nil
		}
		if args.Limit == 0 {
			args.Limit = 5
		}
		c, err := s.m.pg.ForAccount(accountID).SearchConfig()
		if err != nil {
			return actool.Errorf("research configuration or credential vault unavailable"), nil
		}
		if !c.Enabled {
			return actool.Errorf("research disabled in account settings"), nil
		}
		host := map[string]string{"mwmbl": "api.mwmbl.org", "ddgs": "html.duckduckgo.com", "tavily": "api.tavily.com", "exa": "api.exa.ai", "linkup": "api.linkup.so"}[c.Backend]
		if host == "" {
			return actool.Errorf("research policy unavailable"), nil
		}
		if err = platformpolicy.CheckHost(host); err != nil {
			return actool.Errorf("search destination blocked by execution policy"), nil
		}
		transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("search provider redirects are not allowed")
		}}
		results, err := actool.WebSearchProbe(ctx, actool.WebSearchConfig{HTTPClient: client, Backend: c.Backend, TavilyAPIKey: c.TavilyKey, ExaAPIKey: c.ExaKey, LinkupAPIKey: c.LinkupKey}, args.Query, args.Limit)
		if err != nil {
			return actool.Errorf(fmt.Sprintf("research via %s failed: %s", c.Backend, err.Error())), nil
		}
		return jsonResult(map[string]any{"provider": c.Backend, "query": args.Query, "retrieved_at": time.Now().UTC().Format(time.RFC3339), "results": results, "untrusted": true, "note": "Public references only. Check original sources and affected versions. Research is not execution evidence or finding verification."})
	})
}
