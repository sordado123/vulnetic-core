//go:build !windows

package reverseagent

import (
	"context"
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
)

func shellCommand(raw, directory string) (*exec.Cmd, error) {
	c := exec.Command("/bin/bash", "-c", raw)
	c.Dir = directory
	c.Env = os.Environ()
	return c, nil
}
func serveNative(context.Context, string, string, ssh.Channel, *ssh.Request) bool { return false }
