package reverseagent

import (
	"bufio"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testWindowsJobTree(t *testing.T, dir string) {
	script := `$p=New-Object System.Diagnostics.Process; $p.StartInfo.FileName=(Join-Path $PSHOME 'powershell.exe'); $p.StartInfo.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60'; $p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true; [void]$p.Start(); [Console]::WriteLine($p.Id); Start-Sleep -Seconds 60`
	c, err := shellCommand(EncodeNative(NativeCommand{Kind: "exec", Command: script}), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareProcess(c); err != nil {
		t.Fatal(err)
	}
	defer killProcess(c)
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = startedProcess(c); err != nil {
		t.Fatal(err)
	}
	pidLine := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); pidLine <- line }()
	var line string
	select {
	case line = <-pidLine:
	case <-time.After(15 * time.Second):
		t.Fatal("supervised child did not start")
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(line), 10, 32)
	if err != nil {
		t.Fatal("missing child PID", line, err)
	}
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(child)
	killProcess(c)
	_ = c.Wait()
	result, err := windows.WaitForSingleObject(child, 5000)
	if err != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatal("command cancellation left its child running", result, err)
	}
}
