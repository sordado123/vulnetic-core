package db

import (
	"reflect"
	"testing"
)

func TestCredentialEnvironment(t *testing.T) {
	password := "quotes'\" $HOME $(cmd) `cmd` \n unicode-ç"
	creds := []TaskCredential{{ID: 12, Password: password}, {ID: 13, Password: ""}}
	name := CredentialPasswordEnv(12)
	for _, command := range []string{"os.environ['" + name + "']", "$env:" + name, "${" + name + "} ${" + name + "}"} {
		got, err := CredentialEnvironment(command, creds)
		if err != nil || !reflect.DeepEqual(got, []string{name + "=" + password}) {
			t.Fatalf("credential environment was modified or duplicated: %v", err)
		}
	}
	for _, command := range []string{"{{cred:12:password}}", "$VULNETIC_CRED_999_PASSWORD", "$VULNETIC_CRED_13_PASSWORD"} {
		if _, err := CredentialEnvironment(command, creds); err == nil {
			t.Fatalf("expected unavailable credential to prevent execution")
		}
	}
	if got, err := CredentialEnvironment("echo harmless", creds); err != nil || len(got) != 0 {
		t.Fatal("unrelated command received credentials")
	}
}
