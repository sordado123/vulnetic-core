package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sordado123/vulnetic/agent"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/sshexec"
)

// Inventory is run by the selected executor, never by the platform process.
const executorInventory = `import concurrent.futures,json,os,platform,shutil,subprocess,tempfile
tools={'python3':['--version'],'curl':['--version'],'nmap':['--version'],'httpx':['-version'],'katana':['-version'],'ffuf':['-V'],'nuclei':['-version'],'sqlmap':['--version'],'whatweb':['--version'],'chromium':['--version'],'node':['--version'],'pdfinfo':['-v'],'pdftotext':['-v'],'pdftoppm':['-v'],'tesseract':['--version']}
def check(item):
 name,args=item; binary=shutil.which(name)
 if not binary: return {'name':name,'available':False}
 try:
  run=subprocess.run([binary]+args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=3,text=True,errors='replace')
  return {'name':name,'available':True,'version':run.stdout.strip()[:500],'exit_code':run.returncode}
 except Exception: return {'name':name,'available':True,'version_unavailable':True}
writable=False
try:
 with tempfile.TemporaryFile(dir=os.getcwd()) as probe: probe.write(b'vulnetic preflight'); writable=True
except OSError: pass
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool: inventory=list(pool.map(check,tools.items()))
print(json.dumps({'os':platform.system().lower(),'workspace_writable':writable,'privileged':os.geteuid()==0 if hasattr(os,'geteuid') else None,'tools':inventory,'note':'Detected programs are not verified distributions. No tools were installed and no lease was renewed.'}))`

const windowsInventory = `$ErrorActionPreference='Stop'
$tools=@('python3.exe','python.exe','curl.exe','nmap.exe','httpx.exe','katana.exe','ffuf.exe','nuclei.exe','node.exe','chrome.exe','msedge.exe')
$inventory=@(foreach($name in $tools){$command=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if($command){[pscustomobject]@{name=$name;available=$true;version=$command.Version.ToString();version_source='executable_metadata'}}else{[pscustomobject]@{name=$name;available=$false}}})
$writable=$false
$probe=Join-Path (Get-Location) ('.vulnetic-preflight-'+[Guid]::NewGuid().ToString('N'))
try{$stream=[IO.File]::Open($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Close();$writable=$true}finally{if(Test-Path -LiteralPath $probe){Remove-Item -LiteralPath $probe}}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
@{os='windows';workspace_writable=$writable;privileged=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);tools=$inventory;note='Executable metadata does not verify tool distribution or runtime compatibility. No package was installed and no lease was renewed.'} | ConvertTo-Json -Depth 5 -Compress`

func (s *Server) executionAssessmentTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("inspect_executor", "Inspect the selected executor's workspace and installed assessment programs/versions. Does not install packages, elevate privileges, scan a target or renew authorization. Use this instead of assuming a program exists.", objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			ex, ok := ri.Executor.(*sshexec.LazyExecutor)
			if !ok || ex == nil || ri.AccountID <= 0 || ex.AccountID != ri.AccountID {
				return actool.Errorf("authenticated customer executor required"), nil
			}
			if ex.ExecutionOS() == "windows" {
				in, _ := json.Marshal(map[string]any{"command": windowsInventory, "timeout_ms": 20000})
				return actool.NewBash().Call(ctx, in, &actool.ToolContext{Executor: ex})
			}
			return remotePython(ctx, executorInventory, nil, 20000, &actool.ToolContext{Executor: ex})
		}),
		wrTool("diagnose_executor", "Check the selected executor's connection to an account-configured research endpoint through the real gateway/DNS/TLS transport. Makes one HEAD request, never a paid model call. Does not renew access.", objSchema(map[string]any{"provider": map[string]any{"type": "string", "enum": []string{"mwmbl", "ddgs", "tavily", "exa", "linkup"}}}, "provider"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			ex, ok := ri.Executor.(*sshexec.LazyExecutor)
			if !ok || ex == nil || ri.AccountID <= 0 || ex.AccountID != ri.AccountID {
				return actool.Errorf("authenticated customer executor required"), nil
			}
			var args struct {
				Provider string `json:"provider"`
			}
			if json.Unmarshal(in, &args) != nil || researchProviderHost(args.Provider) == "" {
				return actool.Errorf("unsupported research provider"), nil
			}
			cfg, err := s.m.pg.ForAccount(ri.AccountID).SearchConfig()
			if err != nil {
				return actool.Errorf("research policy unavailable"), nil
			}
			allowed := cfg.Backend == args.Provider
			for _, name := range cfg.Fallbacks {
				allowed = allowed || name == args.Provider
			}
			if !allowed {
				return actool.Errorf("provider not configured for this account"), nil
			}
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+researchProviderHost(args.Provider)+"/", nil)
			start := time.Now()
			resp, err := client.Do(req)
			out := map[string]any{"provider": args.Provider, "executor_id": ri.ExecutorID, "duration_ms": time.Since(start).Milliseconds(), "stage": "https", "status": actool.ResearchErrorCode(err), "paid_model_call": false}
			if resp != nil {
				resp.Body.Close()
				out["http_status"] = resp.StatusCode
				out["note"] = "Any HTTP status proves DNS/TCP/TLS reachability, not API key validity or search success."
			}
			result, _ := jsonResult(out)
			result.IsError = err != nil
			return result, nil
		}),
		s.toolParseAssessmentOutput(),
		s.toolNetworkInventory(),
		s.toolReadWebPage(),
		s.toolBrowserSession(),
	}
}
