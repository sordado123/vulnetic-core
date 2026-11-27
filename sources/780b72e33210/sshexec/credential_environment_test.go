package sshexec

import (
	"strings"
	"testing"
)

func TestCredentialEnvironmentAcrossGateway(t *testing.T) {
	command := `python3 -c "import os; authenticate(os.environ['VULNETIC_CRED_2_PASSWORD'])"`
	app := &LazyExecutor{SecretResolver: func(string) ([]string, error) { return []string{"VULNETIC_CRED_2_PASSWORD=fixture only"}, nil }}
	env, err := app.commandEnvironment(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := &LazyExecutor{}
	forwarded, err := gate.commandEnvironment(command, env)
	if err != nil || len(forwarded) != 1 || !strings.HasSuffix(forwarded[0], "=fixture only") {
		t.Fatal("gateway refused resolved credentials", err)
	}
	if _, err = gate.commandEnvironment(command, nil); err == nil {
		t.Fatal("unresolved credential accepted")
	}
	if _, err = gate.commandEnvironment(`echo {{cred:2}}`, env); err == nil {
		t.Fatal("legacy source substitution accepted")
	}
}
