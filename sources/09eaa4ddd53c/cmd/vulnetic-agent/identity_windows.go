package main

import (
	"fmt"
	"io"

	"github.com/sordado123/vulnetic/internal/agentidentity"
)

var version = "dev"

func windowsVersion() string {
	if version == "dev" {
		return agentidentity.Windows().Version
	}
	return version
}

func describeWindowsExecutor(out io.Writer) {
	m := agentidentity.Windows()
	fmt.Fprintf(out, "%s %s\n%s\nBrand: %s (file metadata is not a verified publisher signature).\n", m.ProductName, windowsVersion(), m.Description, m.Brand)
	fmt.Fprintln(out, "Run in a non-administrator terminal. No service, account, scheduled task or automatic startup is created.")
	fmt.Fprintln(out, "It connects outward to your selected Vulnetic endpoint and accepts authenticated remote commands with your current user's file and network permissions.")
	fmt.Fprintln(out, "Use a dedicated VM/VPS or an already restricted account. A workspace directory is not a Windows sandbox.")
	fmt.Fprintln(out, "Keep the terminal open. Reconnection after a network or server interruption never renews the original access deadline.")
	fmt.Fprintln(out, "Ctrl+C stops execution. After closing the process or rebooting this machine, generate and run a new connection command; there is no automatic restart.")
	fmt.Fprintln(out, "Connection credentials stay in memory; the one-use input is removed before connecting. Workspace files are preserved.")
	fmt.Fprintln(out, "Unsigned builds have an unverified publisher. Do not disable protection or add antivirus exclusions to run them.")
	fmt.Fprintln(out, "Antivirus results apply to the tested build and environment; they do not guarantee acceptance by every security product.")
}
