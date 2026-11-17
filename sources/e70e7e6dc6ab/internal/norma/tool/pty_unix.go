// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
//go:build !windows

package tool

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// startPTY launches cmd attached to a new pseudo-terminal of the given size and
// returns the master file (read output / write input). Unix implementation via
// creack/pty. ptySupported reports platform support.
func startPTY(cmd *exec.Cmd, rows, cols int) (*os.File, error) {
	return pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

func ptySupported() bool { return true }
