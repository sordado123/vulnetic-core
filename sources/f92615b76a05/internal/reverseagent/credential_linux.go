package reverseagent

import (
	"os"
	"syscall"
)

func privateStateCredential(info os.FileInfo) bool {
	if info.Mode().Perm()&0077 == 0 {
		return true
	}
	// systemd can expose its read-only credential as root:root 0440 inside its private mount.
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().Perm() == 0440 && stat.Uid == 0 && stat.Gid == 0
}
