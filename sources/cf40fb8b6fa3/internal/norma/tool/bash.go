// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/internal/norma/permission"
)

// catastrophicBash matches a small set of irreversibly destructive commands
// that are hard-denied regardless of mode (NFR-10). This is a safety floor, not
// a full sandbox — hosts should still gate Bash via CanUseTool.
var catastrophicBash = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/(\s|$)`), // rm -rf /
	regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`),                               // fork bomb
	regexp.MustCompile(`\bmkfs\.\w+\s+/dev/`),                                                      // format a device
	regexp.MustCompile(`\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd)`),                                       // overwrite a disk
}

// disallowedAutoBackground lists commands that must never be silently moved to
// the background on timeout.
var disallowedAutoBackground = []string{"sleep"}

// NewBash builds the Bash tool: run a shell command with a timeout, optionally in
// the background.
func NewBash() CoreTool {
	props := map[string]any{
		"command":    map[string]any{"type": "string", "description": "The shell command to execute."},
		"timeout_ms": map[string]any{"type": "integer", "description": "Timeout in ms (default 120000, max 600000)."},
	}
	desc := "Executes a shell command in the working directory and returns combined stdout and stderr. Use for running tests, builds, package managers, and git. Prefer the dedicated file tools for file work."
	prompt := "The command runs through the shell, so you are not limited to one command: " + shellChainingHint() + ", use pipes, and pass multi-line scripts or heredocs. For anything beyond a simple one-liner — loops, parsing, string/JSON handling, HTTP logic, computation — prefer writing a short script (Python, Node, shell, etc.) and executing it (e.g. via a heredoc or by writing a file then running it) rather than forcing everything into a single command. A timeout (default 120s, max 600s) applies. Avoid commands needing interactive input."
	if !BackgroundTasksDisabled() {
		props["run_in_background"] = map[string]any{
			"type":        "boolean",
			"description": "Run in the background and return immediately; read its output later with TaskOutput or Read, and you are notified when it completes. A foreground command that exceeds its timeout is also moved to the background automatically.",
		}
		desc += " Set run_in_background to return immediately and read the output later."
	}
	return Build(Spec{
		Name:        "Bash",
		Description: desc,
		Prompt:      prompt,
		Schema: map[string]any{
			"type":       "object",
			"properties": props,
			"required":   []any{"command"},
		},
		Permissions: bashPermissions,
		Run:         runBash,
	})
}

// shellChainingHint names the actual chaining syntax this host's shell
// accepts, computed once (at tool-build time, via runtime.GOOS — the same
// check shellCmd() in task.go uses to pick the shell binary) so every agent
// sees the correct syntax from its very first look at the tool spec, instead
// of discovering it by trial and error. shellCmd() always launches Windows
// PowerShell (powershell.exe, i.e. 5.1), which — unlike bash and unlike
// PowerShell 7+'s pwsh.exe — has no && or || statement separator; only ";"
// chains commands unconditionally there (conditional chaining needs
// `if ($?) { ... }`).
func shellChainingHint() string {
	if runtime.GOOS == "windows" {
		return "this host's shell is Windows PowerShell, which has no && or || — chain steps with ; (unconditional) or `if ($?) { ... }` (conditional on success); && and || are parse errors here, not conditional-execution operators"
	}
	return "chain steps with && or ;"
}

// windowsSeparatorHint appends a corrective note to a failed command's output
// when it used && or || on this host's shell (Windows PowerShell, per
// shellCmd() in task.go) — the same syntax mistake the tool description in
// NewBash already warns against. Reinforcing it again right on the failure,
// in the same tool_result the model reads next, is what actually stops the
// mistake from repeating across the rest of the run: the static prompt text
// is read once at the top of context and can scroll out of a long session's
// effective attention, but this note lands exactly where and when the model
// is about to decide how to retry.
func windowsSeparatorHint(command string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	if !strings.Contains(command, "&&") && !strings.Contains(command, "||") {
		return ""
	}
	return "\n\n[hint: this shell is Windows PowerShell, not bash — && and || are not statement separators here and will always fail this way. Use ; to chain commands unconditionally, or `if ($?) { ... }` for conditional chaining. This applies to every Bash call for the rest of this task, not just this one.]"
}

func bashPermissions(_ context.Context, input json.RawMessage, _ permission.Context) permission.Decision {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	for _, re := range catastrophicBash {
		if re.MatchString(in.Command) {
			return permission.Denied("denied: command appears irreversibly destructive and is blocked by the safety floor")
		}
	}
	return permission.AskUser("run shell command: " + in.Command)
}

func runBash(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error) {
	var in struct {
		Command         string `json:"command"`
		TimeoutMS       int    `json:"timeout_ms"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return Errorf("Error: command is required"), nil
	}
	timeout := 120 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
	}

	// Background-capable path: requires a task manager on the context.
	if tc != nil && tc.Tasks != nil && !BackgroundTasksDisabled() {
		return runBashManaged(ctx, tc, in.Command, timeout, in.RunInBackground)
	}
	// Fallback: synchronous execution (unchanged legacy behavior).
	return runBashSync(ctx, tc, in.Command, timeout)
}

// runBashManaged runs the command through the task manager, supporting explicit
// background launch and timeout auto-backgrounding.
func runBashManaged(ctx context.Context, tc *ToolContext, command string, timeout time.Duration, explicitBG bool) (Result, error) {
	spec := SpawnSpec{Command: command, Kind: KindBash, WorkingDir: tc.WorkingDir, Description: short(command), Env: tc.Env, Executor: tc.Executor}

	if explicitBG {
		t, err := tc.Tasks.Spawn(spec)
		if err != nil {
			return Errorf("Error: failed to start background command: " + err.Error()), nil
		}
		tc.Tasks.Background(t.ID)
		return Text(fmt.Sprintf(
			"Running in background as %s. Output file: %s\nUse TaskOutput{task_id:%q} or Read to read its output; you are notified when it completes.",
			t.ID, t.OutputPath, t.ID)), nil
	}

	t, finished, output, err := tc.Tasks.RunForeground(ctx, spec, timeout)
	if err != nil {
		if t != nil {
			tc.Tasks.Forget(t.ID)
		}
		return Errorf("Error: " + err.Error()), nil
	}
	if finished {
		info, _ := tc.Tasks.Get(t.ID)
		tc.Tasks.Forget(t.ID)
		if info.Status == TaskFailed {
			if strings.TrimSpace(output) == "" {
				output = "(no output)"
			}
			return Errorf(fmt.Sprintf("%s\n\n[exit code %d]%s", Capture(tc, output), info.ExitCode, windowsSeparatorHint(command))), nil
		}
		if strings.TrimSpace(output) == "" {
			output = "(command produced no output)"
		}
		return Text(Capture(tc, output)), nil
	}

	// Timed out while still running.
	if autoBackgroundAllowed(command) {
		tc.Tasks.Background(t.ID)
		return Text(fmt.Sprintf(
			"Command still running after %s; moved to background as %s. Output file: %s\nUse TaskOutput{task_id:%q} to read its output; you are notified when it completes.",
			timeout, t.ID, t.OutputPath, t.ID)), nil
	}
	out, _ := tc.Tasks.Output(t.ID, 0)
	tc.Tasks.Kill(t.ID)
	tc.Tasks.Forget(t.ID)
	return Errorf(Capture(tc, out) + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
}

// runBashSync is the original blocking implementation, used when no task manager
// is available (background execution disabled).
func runBashSync(ctx context.Context, tc *ToolContext, command string, timeout time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dir string
	var env []string
	executor := Executor(LocalExecutor{})
	if tc != nil {
		dir, env = tc.WorkingDir, tc.Env
		if tc.Executor != nil {
			executor = tc.Executor
		}
	}
	var buf bytes.Buffer
	handle, startErr := executor.Start(cctx, dir, env, command, &buf)
	var err error
	if startErr != nil {
		err = startErr
	} else {
		err = handle.Wait()
	}

	out := Capture(tc, buf.String())
	if cctx.Err() == context.DeadlineExceeded {
		return Errorf(out + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
	}
	if err != nil {
		if handle != nil {
			if code := handle.ExitCode(err); code >= 0 {
				if out == "" {
					out = "(no output)"
				}
				return Errorf(fmt.Sprintf("%s\n\n[exit code %d]%s", out, code, windowsSeparatorHint(command))), nil
			}
		}
		return Errorf(fmt.Sprintf("%s\n\n[failed to run: %v]%s", out, err, windowsSeparatorHint(command))), nil
	}
	if strings.TrimSpace(out) == "" {
		out = "(command produced no output)"
	}
	return Text(out), nil
}

// autoBackgroundAllowed reports whether a timed-out command may be moved to the
// background instead of being killed.
func autoBackgroundAllowed(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	base := fields[0]
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	for _, d := range disallowedAutoBackground {
		if base == d {
			return false
		}
	}
	return true
}
