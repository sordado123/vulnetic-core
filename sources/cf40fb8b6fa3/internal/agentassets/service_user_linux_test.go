//go:build linux

package agentassets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestManagedServiceUserReinstallation(t *testing.T) {
	home, account, uid, _ := workspaceFixture(t)
	_, script, ok := strings.Cut(InstallScript, "<<'USER'\n")
	if !ok {
		t.Fatal("service user check missing")
	}
	script, _, ok = strings.Cut(script, "\nUSER\n")
	if !ok {
		t.Fatal("service user check terminator missing")
	}
	// Mock usermod: this fixture must never change the host's real nobody account.
	prefix := `import pwd,subprocess,sys
original=pwd.getpwnam(sys.argv[1])
identity=pwd.struct_passwd((original.pw_name,original.pw_passwd,original.pw_uid,original.pw_gid,original.pw_gecos,sys.argv[2],sys.argv[4]))
pwd.getpwnam=lambda name: identity
subprocess.run=lambda args,check: print('FIXTURE_REPAIR' if args[:2]==['usermod','--shell'] and args[3]==sys.argv[1] else 'INVALID_REPAIR')
sys.argv=sys.argv[:4]
`
	for _, tc := range []struct {
		name, shell, marker string
		mode                os.FileMode
		success, repair     bool
	}{
		{"legacy_bash", "/bin/bash", strconv.Itoa(uid), 0600, true, true},
		{"already_nologin", "/usr/sbin/nologin", strconv.Itoa(uid), 0600, true, false},
		{"wrong_identity", "/bin/bash", "0", 0600, false, false},
		{"writable_marker", "/bin/bash", strconv.Itoa(uid), 0666, false, false},
		{"unknown_shell", "/unexpected/shell", strconv.Itoa(uid), 0600, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "service-user.uid")
			if err := os.WriteFile(marker, []byte(tc.marker), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(marker, tc.mode); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python3", "-c", prefix+script, account, home, marker, tc.shell)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.success || strings.Contains(string(out), "FIXTURE_REPAIR") != tc.repair || strings.Contains(string(out), "INVALID_REPAIR") {
				t.Fatalf("unexpected repair result: %v %s", err, out)
			}
		})
	}
}
