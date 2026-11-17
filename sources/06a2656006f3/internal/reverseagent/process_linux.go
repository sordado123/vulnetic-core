package reverseagent

import (
	"os/exec"
	"syscall"
)

func prepareProcess(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func killProcess(command *exec.Cmd) {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}

func startedProcess(*exec.Cmd) error { return nil }
