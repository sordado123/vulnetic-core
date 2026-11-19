package server

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func linkTestDirectory(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal("mandatory filesystem link check unavailable:", err)
		}
		if output, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Fatalf("mandatory junction check unavailable: %v %s", junctionErr, output)
		}
	}
}
