// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
//go:build !windows

package tool

import (
	"os"
	"os/exec"
	"syscall"
)

// setDetached puts the child in its own process group so it survives the
// per-turn context and can be killed as a whole tree.
func setDetached(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// treeKill terminates the process group, falling back to the lone process.
func treeKill(p *os.Process) {
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		_ = p.Kill()
	}
}
