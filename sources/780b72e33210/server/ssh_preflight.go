package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/reverseagent"
)

// This key is set only while running the fixed metadata probe, never from API or model arguments.
type executorPreflightContextKey struct{}

func (s *Server) sshPreflight(ctx context.Context, accountID, targetID int64) (json.RawMessage, error) {
	ex, closeExecutor, err := s.trackRemoteExecutor(accountID, targetID, fmt.Sprintf(".vulnetic/accounts/%d/preflight", accountID))
	if err != nil {
		return nil, err
	}
	defer closeExecutor()
	var output bytes.Buffer
	command := "python3 -c " + shellQuote(`import json,os,shutil,stat,tempfile
result={"os":"linux","hostname":os.uname().nodename,"uid":os.geteuid(),"tools":{name:shutil.which(name) is not None for name in ("bash","python3","curl","dig","git","node","rg")},"directory_writable":False,"free_bytes":shutil.disk_usage(".").free,"traffic_capture":"unavailable"}
try:
 uid=os.geteuid()
 if uid==0: raise RuntimeError("agent_must_not_be_root")
 account=os.path.dirname(os.getcwd())
 for name in ("sessions","tasks","drafts","tool-tests","notifications","side-questions"):
  path=os.path.join(account,name)
  try: os.mkdir(path,0o700)
  except FileExistsError: pass
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or not os.access(path,os.W_OK|os.X_OK): raise RuntimeError("managed_directory_not_owned_or_writable: "+name)
 with tempfile.TemporaryFile(dir=".") as f: f.write(b"vulnetic-preflight")
 result["directory_writable"]=True
except (OSError,RuntimeError): result["workspace_error"]="managed workspace directories must be owned and writable by the non-root agent user; ask the VPS administrator to repair the managed directories"
print(json.dumps(result))`)

	if ex.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "metadata"})
	}
	ctx = context.WithValue(ctx, executorPreflightContextKey{}, true)
	handle, err := ex.Start(ctx, "", nil, command, &output)
	if err != nil {
		return nil, err
	}
	if err = handle.Wait(); err != nil {
		return nil, fmt.Errorf("remote preflight failed; verify python3 and SSH permissions")
	}
	var result struct {
		Tools          map[string]bool `json:"tools"`
		Writable       bool            `json:"directory_writable"`
		Free           int64           `json:"free_bytes"`
		WorkspaceError string          `json:"workspace_error"`
	}
	if err = json.Unmarshal(output.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("invalid remote preflight result")
	}
	if result.WorkspaceError != "" {
		return nil, fmt.Errorf("VPS workspace validation failed: %s", result.WorkspaceError)
	}
	if ex.ExecutionOS() == "windows" {
		if !result.Writable || !result.Tools["powershell"] {
			return nil, fmt.Errorf("Windows executor requires PowerShell and a writable workspace")
		}
	} else if !result.Writable || !result.Tools["bash"] || !result.Tools["python3"] || !result.Tools["curl"] {
		return nil, fmt.Errorf("VPS requires bash, python3, curl and a writable workspace")
	}
	if result.Free < 100<<20 {
		return nil, fmt.Errorf("VPS has less than 100 MiB free space")
	}
	return append(json.RawMessage(nil), output.Bytes()...), nil
}

func preflightComplete(target *db.SSHTarget) bool {
	var result struct {
		Tools    map[string]bool `json:"tools"`
		Writable bool            `json:"directory_writable"`
	}
	if json.Unmarshal(target.Preflight, &result) != nil || !result.Writable {
		return false
	}
	if target.OperatingSystem() == "windows" {
		return result.Tools["powershell"]
	}
	return result.Tools["bash"] && result.Tools["python3"] && result.Tools["curl"]
}
