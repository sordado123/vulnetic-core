// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package tool

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/config"
	"io"
	"os/exec"
)

// ExecHandle is a started command, abstracting over a local OS process and a
// remote (SSH) session so Manager's lifecycle tracking (watch/terminate,
// background-task bookkeeping) works identically for both — see
// Manager.Spawn in task.go.
type ExecHandle interface {
	// Wait blocks until the command exits. A non-nil error on a clean
	// non-zero exit is expected; callers read the code via ExitCode rather
	// than asserting a concrete error type (which differs between a local
	// *exec.ExitError and a remote SSH exit-status error).
	Wait() error
	// ExitCode extracts the exit status from the error Wait returned (nil
	// error means 0). Returns -1 when the error does not carry an exit
	// status at all (e.g. a transport failure, not the command itself).
	ExitCode(waitErr error) int
	// Kill terminates the running command (and, for a local process, its
	// process group/tree — see treeKill in task_unix.go/task_windows.go).
	Kill()
}

// Executor starts command, writing its combined stdout+stderr to out, and
// returns a handle to wait on or kill. It decides WHERE a command runs
// (this host, or a remote SSH target) and therefore owns the shell
// selection and environment policy for that destination — neither
// shellCmd() nor withEnv() (local-OS-shaped: os.Environ(), runtime.GOOS)
// is meaningful for a remote target, so an Executor never receives them
// pre-applied; it is given only the extra "KEY=VALUE" entries a caller
// wants layered on top (proxy/CA vars, etc.) via extraEnv.
type Executor interface {
	Start(ctx context.Context, dir string, extraEnv []string, command string, out io.Writer) (ExecHandle, error)
}

// LocalExecutor runs command on this host — the behavior every task had
// before Fase B's remote executor existed. Its Start is exactly the
// exec.CommandContext + shellCmd()/withEnv() construction Spawn used to do
// inline; refactoring it behind this interface changes nothing for a task
// that has no ssh_target_id (the default).
type LocalExecutor struct{}

type localExecHandle struct{ cmd *exec.Cmd }

func (LocalExecutor) Start(ctx context.Context, dir string, extraEnv []string, command string, out io.Writer) (ExecHandle, error) {
	if config.SaaSMode() {
		return nil, errors.New("policy_denied: local execution is disabled in SaaS")
	}
	shell, flags := shellCmd()
	cmd := exec.CommandContext(ctx, shell, append(flags, command)...)
	cmd.Dir = dir
	cmd.Env = withEnv(extraEnv)
	cmd.Stdout = out
	cmd.Stderr = out
	setDetached(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &localExecHandle{cmd: cmd}, nil
}

func (h *localExecHandle) Wait() error { return h.cmd.Wait() }

func (h *localExecHandle) ExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (h *localExecHandle) Kill() {
	if h.cmd.Process != nil {
		treeKill(h.cmd.Process)
	}
}
