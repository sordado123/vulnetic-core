//go:build linux

package agentassets

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func workspaceFixture(t *testing.T) (string, string, int, int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated installer fixture")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err = os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(parent, "workspace")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(home, uid, gid); err != nil {
		t.Fatal(err)
	}
	return home, account.Username, uid, gid
}
func TestInstallerRepairsOnlyManagedDirectoryMetadata(t *testing.T) {
	home, account, uid, _ := workspaceFixture(t)
	sessions := filepath.Join(home, ".vulnetic/accounts/4/sessions")
	if err := os.MkdirAll(sessions, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(sessions, "retained-file")
	if err := os.WriteFile(marker, []byte("retained-content"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(marker)
	cmd := exec.Command("python3", "-c", prepareWorkspacePython, account, home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	info, err := os.Stat(sessions)
	if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != uid || info.Mode().Perm() != 0700 {
		t.Fatal("legacy managed parent was not repaired", err)
	}
	after, _ := os.Stat(marker)
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "retained-content" || after.Mode() != before.Mode() || after.Sys().(*syscall.Stat_t).Uid != before.Sys().(*syscall.Stat_t).Uid {
		t.Fatal("installer changed an existing file")
	}
}
func TestInstallerRejectsWorkspaceSymlink(t *testing.T) {
	home, account, _, _ := workspaceFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".vulnetic")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(outside)
	cmd := exec.Command("python3", "-c", prepareWorkspacePython, account, home)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "Unsafe managed workspace") {
		t.Fatal("unsafe managed link accepted", err, string(out))
	}
	after, _ := os.Stat(outside)
	if after.Sys().(*syscall.Stat_t).Uid != before.Sys().(*syscall.Stat_t).Uid {
		t.Fatal("installer changed ownership outside the workspace")
	}
}
func TestWorkspacePreparationPrecedesEnrollmentAndServiceStart(t *testing.T) {
	preparation := strings.Index(InstallScript, "<<'WORKSPACE'")
	enrollment := strings.Index(InstallScript, `printf '%s\n' "$VULNETIC_ENROLL_TOKEN"`)
	start := strings.Index(InstallScript, `systemctl enable --now`)
	if preparation < 0 || enrollment < preparation || start < enrollment {
		t.Fatal("workspace preparation occurs after activation")
	}
	for _, guard := range []string{"User=vulnetic-agent", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "RuntimeMaxSec=", "os.setgroups([])", "os.setuid(uid)", "os.O_NOFOLLOW"} {
		if !strings.Contains(InstallScript, guard) {
			t.Fatal("installer guard missing", guard)
		}
	}
}
