package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/reverseagent"
)

func (s *Server) sshPreflight(ctx context.Context, accountID, targetID int64) (json.RawMessage, error) {
	ex, closeExecutor, err := s.trackRemoteExecutor(accountID, targetID, fmt.Sprintf(".vulnetic/accounts/%d/preflight", accountID))
	if err != nil {
		return nil, err
	}
	defer closeExecutor()
	var output bytes.Buffer
	command := `python3 -c 'import json,os,shutil,tempfile
tools={name:shutil.which(name) is not None for name in ("bash","python3","curl")}
with tempfile.TemporaryFile(dir=".") as f: f.write(b"vulnetic-preflight")
print(json.dumps({"tools":tools,"directory_writable":True,"free_bytes":shutil.disk_usage(".").free,"traffic_capture":"unavailable"}))'`
	if ex.ExecutionOS() == "windows" {
		command = reverseagent.EncodeNative(reverseagent.NativeCommand{Kind: "metadata"})
	}
	handle, err := ex.Start(ctx, "", nil, command, &output)
	if err != nil {
		return nil, err
	}
	if err = handle.Wait(); err != nil {
		return nil, fmt.Errorf("remote preflight failed; verify python3 and SSH permissions")
	}
	var result struct {
		Tools    map[string]bool `json:"tools"`
		Writable bool            `json:"directory_writable"`
		Free     int64           `json:"free_bytes"`
	}
	if err = json.Unmarshal(output.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("invalid remote preflight result")
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
