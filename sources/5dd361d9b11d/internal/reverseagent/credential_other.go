//go:build !linux

package reverseagent

import "os"

func privateStateCredential(info os.FileInfo) bool {
	return info.Mode().Perm()&0077 == 0
}
