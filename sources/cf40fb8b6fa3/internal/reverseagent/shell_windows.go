package reverseagent

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

func powershellPath() string {
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	return filepath.Join(directory, "WindowsPowerShell", "v1.0", "powershell.exe")
}

func nativeDirectory(base, relative string) (string, error) {
	if relative == "" {
		relative = "."
	}
	relative = filepath.FromSlash(relative)
	if !filepath.IsLocal(relative) {
		return "", errors.New("remote directory must remain in its workspace")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err = root.MkdirAll(relative, 0700); err != nil {
		return "", err
	}
	return filepath.Join(base, relative), nil
}

func shellCommand(raw, directory string) (*exec.Cmd, error) {
	spec, err := DecodeNative(raw)
	if err != nil || spec.Kind != "exec" {
		return nil, errors.New("native PowerShell command required")
	}
	dir, err := nativeDirectory(directory, spec.Directory)
	if err != nil {
		return nil, err
	}
	script := "$ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; $global:LASTEXITCODE=0; try { & {\n" + spec.Command + "\n}; if (-not $?) { exit 1 }; exit $LASTEXITCODE } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, v := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], v)
	}
	c := exec.Command(powershellPath(), "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat","Text", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	c.Dir = dir
	c.Env = os.Environ()
	for _, item := range spec.Env {
		name, value, ok := strings.Cut(item, "=")
		if !ok || name == "" || strings.ContainsAny(name, "\x00\r\n") || strings.ContainsRune(value, 0) {
			return nil, errors.New("invalid command environment")
		}
		for i := len(c.Env) - 1; i >= 0; i-- {
			key, _, _ := strings.Cut(c.Env[i], "=")
			if strings.EqualFold(name, key) {
				c.Env = append(c.Env[:i], c.Env[i+1:]...)
			}
		}
		c.Env = append(c.Env, item)
	}
	return c, nil
}

func serveNative(ctx context.Context, raw, directory string, channel ssh.Channel, request *ssh.Request) bool {
	spec, err := DecodeNative(raw)
	if err != nil || spec.Kind == "exec" {
		return false
	}
	_ = request.Reply(true, nil)
	defer channel.Close()
	dir, err := nativeDirectory(directory, spec.Directory)
	if err == nil {
		switch spec.Kind {
		case "upload":
			err = nativeUpload(ctx, dir, spec.Name, spec.Expected, channel, channel)
		case "skill":
			var installed string
			installed, err = nativeSkill(ctx, dir, spec.Command, spec.Name, spec.Expected)
			if err == nil {
				_, err = fmt.Fprintln(channel, filepath.ToSlash(installed))
			}
		case "resolve":
			var records []net.IPAddr
			var canonical string
			records, err = net.DefaultResolver.LookupIPAddr(ctx, spec.Name)
			if err == nil {
				canonical, err = net.DefaultResolver.LookupCNAME(ctx, spec.Name)
			}
			if err == nil {
				addresses := make([]string, 0, len(records))
				for _, r := range records {
					addresses = append(addresses, r.IP.String())
				}
				err = json.NewEncoder(channel).Encode(map[string]any{"addresses": addresses, "names": []string{canonical}})
			}
		case "metadata":
			var probe *os.File
			probe, err = os.CreateTemp(dir, ".vulnetic-preflight-")
			if err != nil {
				break
			}
			_, err = probe.Write([]byte("vulnetic-preflight"))
			closeErr := probe.Close()
			_ = os.Remove(probe.Name())
			if err == nil {
				err = closeErr
			}
			if err != nil {
				break
			}
			path, e := windows.UTF16PtrFromString(dir)
			err = e
			var free uint64
			if err == nil {
				err = windows.GetDiskFreeSpaceEx(path, &free, nil, nil)
			}
			if err == nil {
				_, psErr := os.Stat(powershellPath())
				_, curlErr := exec.LookPath("curl.exe")
				_, pythonErr := exec.LookPath("python3.exe")
				err = json.NewEncoder(channel).Encode(map[string]any{"os": "windows", "shell": "powershell", "tools": map[string]bool{"powershell": psErr == nil, "curl": curlErr == nil, "python3": pythonErr == nil}, "directory_writable": true, "free_bytes": free, "traffic_capture": "unavailable"})
			}
		}
	}
	status := uint32(0)
	if err != nil {
		status = 1
		_, _ = fmt.Fprintln(channel.Stderr(), "remote native operation failed")
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	return true
}
