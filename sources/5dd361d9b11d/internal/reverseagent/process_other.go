//go:build !linux && !windows

package reverseagent

import (
	"errors"
	"os/exec"
)

func prepareProcess(command *exec.Cmd) error {
	return errors.New("the temporary executor requires Linux")
}
func killProcess(command *exec.Cmd) {
	if command.Process != nil {
		_ = command.Process.Kill()
	}
}

func startedProcess(*exec.Cmd) error { return nil }
