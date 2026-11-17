package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentInstallationRequiresOwnedPathsAndSupervisor(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "vulnetic-agent.ABCD1234")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "agent")
	token := filepath.Join(directory, "state", "enrollment")
	if err := os.Mkdir(filepath.Dir(token), 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{executable, token} {
		if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	group := "0::/system.slice/vulnetic-agent-ABCD1234.service\n"
	if err := validateInstallation(executable, token, group); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ executable, token, group string }{{executable, filepath.Join(directory, "other"), group}, {executable, token, "0::/unmanaged"}, {filepath.Join(directory, "other"), token, group}} {
		if validateInstallation(attempt.executable, attempt.token, attempt.group) == nil {
			t.Fatal("unmanaged or unrelated installation accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(token, 0644); err != nil {
			t.Fatal(err)
		}
		if validateInstallation(executable, token, group) == nil {
			t.Fatal("public enrollment input accepted")
		}
	}
}

func TestAgentRejectsRoot(t *testing.T) {
	for _, uid := range []int{0, -1} {
		if err := requireUnprivilegedUser(uid); err == nil {
			t.Fatal("privileged executor accepted")
		}
	}
	if err := requireUnprivilegedUser(10001); err != nil {
		t.Fatal(err)
	}
}

func TestAgentRejectsPrivilegedGroups(t *testing.T) {
	if requirePrivateGroups(0, nil) == nil || requirePrivateGroups(10001, []int{0}) == nil || requirePrivateGroups(10001, []int{10001, 999}) == nil {
		t.Fatal("privileged or supplementary group accepted")
	}
	if err := requirePrivateGroups(10001, []int{10001}); err != nil {
		t.Fatal(err)
	}
}
