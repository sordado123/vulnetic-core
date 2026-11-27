package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"github.com/sordado123/vulnetic/sshexec"
	"io"
	"net/http"
	"strings"
)

func requireRemoteTool(tc *actool.ToolContext) bool {
	if !config.SaaSMode() {
		return true
	}
	if tc == nil || tc.Executor == nil {
		return false
	}
	switch tc.Executor.(type) {
	case actool.LocalExecutor, *actool.LocalExecutor:
		return false
	}
	return true
}

func remotePython(ctx context.Context, code string, params map[string]any, timeoutMs int, tc *actool.ToolContext) (actool.Result, error) {
	if tc == nil || tc.Executor == nil {
		return actool.Errorf("select a verified VPS; local execution is disabled"), nil
	}
	if params == nil {
		params = map[string]any{}
	}
	data, err := json.Marshal(params)
	if err != nil {
		return actool.Errorf("invalid tool parameters"), nil
	}
	if ex, ok := tc.Executor.(*sshexec.LazyExecutor); ok && ex.SecretResolver != nil {
		// Resolve before JSON encoding hides references; values remain environment-only.
		env, err := ex.SecretResolver(string(data))
		if err != nil {
			return actool.Errorf("requested scoped input is unavailable"), nil
		}
		copy := *tc
		copy.Env = append(append([]string{}, tc.Env...), env...)
		tc = &copy
	}
	// JSON stays data; the script and parameters are separately encoded and quoted.
	bootstrap := "import base64,io,json,os,sys; data=base64.b64decode(" + shellQuote(base64.StdEncoding.EncodeToString(data)) + "); params=json.loads(data); os.environ.update({'TOOL_'+k.upper():str(v) for k,v in params.items() if isinstance(v,(str,int,float,bool))}); sys.stdin=io.StringIO(data.decode()); exec(compile(base64.b64decode(" + shellQuote(base64.StdEncoding.EncodeToString([]byte(code))) + "),'<vulnetic-tool>','exec'))"
	command := "python3 -c " + shellQuote(bootstrap)
	if ex, ok := tc.Executor.(*sshexec.LazyExecutor); ok && ex.ExecutionOS() == "windows" {
		command = "$vulneticPython = Get-Command python3.exe,python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $vulneticPython) { Write-Error 'Python 3 is required on this executor'; exit 127 }; & $vulneticPython.Source -c " + ex.Quote(bootstrap)
	}
	in, _ := json.Marshal(map[string]any{"command": command, "timeout_ms": timeoutMs})
	return actool.NewBash().Call(ctx, in, tc)
}

func (s *Server) remoteHTTPTool(ctx context.Context, spec httpExec, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	spec.URL = renderTemplate(spec.URL, params, identity)
	spec.Body = renderTemplate(spec.Body, params, identity)
	for key, value := range spec.Headers {
		spec.Headers[key] = renderTemplate(value, params, identity)
	}
	if strings.TrimSpace(spec.URL) == "" {
		return actool.Errorf("request url is empty"), nil
	}
	ex, ok := tc.Executor.(*sshexec.LazyExecutor)
	if !ok {
		return actool.Errorf("verified gateway executor required"), nil
	}
	if spec.Proxy != "" {
		return actool.Errorf("HTTP proxy forwarding is unavailable for managed tools; configure a direct endpoint"), nil
	}
	transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeoutOr(spec.TimeoutMs, 30000), CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return platformpolicy.CheckHost(r.URL.Hostname())
	}}
	if err := platformpolicy.CheckHost(spec.URL); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	request, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, strings.NewReader(spec.Body))
	if err != nil {
		return actool.Errorf("invalid HTTP request"), nil
	}
	for key, value := range spec.Headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return actool.Errorf("remote HTTP request failed or destination blocked"), nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil {
		return actool.Errorf("remote HTTP response failed"), nil
	}
	result, _ := json.Marshal(map[string]any{"status": response.StatusCode, "body": string(body[:min(len(body), 1048576)]), "truncated": len(body) > 1048576})
	return actool.Text(string(result)), nil
}
