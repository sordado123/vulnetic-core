//go:build linux

package sshexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedWorkspaceCreationUsesUnprivilegedOwner(t *testing.T) {
	base := t.TempDir()
	relative := ".vulnetic/accounts/4/sessions/conv-16"
	cmd := exec.Command("/bin/bash", "-c", commandInDir(relative, nil, "printf workspace-ready"))
	cmd.Dir = base
	out, err := cmd.CombinedOutput()
	if os.Geteuid() == 0 {
		if err == nil || !strings.Contains(string(out), "requires a non-root user") {
			t.Fatal("administrative connection was not rejected", err)
		}
		if _, err := os.Stat(filepath.Join(base, ".vulnetic")); !os.IsNotExist(err) {
			t.Fatal("root created managed directories before being rejected")
		}
		return
	}
	if err != nil || string(out) != "workspace-ready" {
		t.Fatal("unprivileged creation failed", err, string(out))
	}
	info, err := os.Stat(filepath.Join(base, relative))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("workspace is not private", err)
	}
}

func TestCommandInDirKeepsFinalHeredocDelimiterOnItsOwnLine(t *testing.T) {
	command := "cat <<'EOF'\nfirst\nsecond\nEOF"
	cmd := exec.Command("/bin/bash", "-c", commandInDir(t.TempDir(), nil, command))
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "first\nsecond\n" {
		t.Fatalf("heredoc: %v %q", err, out)
	}
}
