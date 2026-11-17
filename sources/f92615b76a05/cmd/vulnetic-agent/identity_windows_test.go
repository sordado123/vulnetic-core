package main

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/sordado123/vulnetic/internal/agentidentity"
)

func TestWindowsCLIRequiresConnectionConsent(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	for _, command := range []string{"-version", "-about", "-install", "-service", "-remove"} {
		flag.CommandLine = flag.NewFlagSet("executor-fixture", flag.ContinueOnError)
		os.Args = []string{"executor-fixture", command}
		err := run()
		if command != "-version" && command != "-about" {
			if err == nil {
				t.Fatal("legacy service command was accepted", command)
			}
		} else if err != nil {
			t.Fatal("informational command attempted a connection", err)
		}
	}
}

func TestWindowsExecutorDisclosureAndIdentity(t *testing.T) {
	var out bytes.Buffer
	describeWindowsExecutor(&out)
	for _, expected := range []string{"Vulnetic Executor", windowsVersion(), "not a verified publisher signature", "unverified publisher", "non-administrator", "authenticated remote commands", "no automatic restart", "never renews", "Workspace files are preserved", "do not guarantee"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("installation disclosure is missing %q", expected)
		}
	}
	if !strings.Contains(out.String(), agentidentity.Windows().Description) {
		t.Fatal("product description missing")
	}
}
