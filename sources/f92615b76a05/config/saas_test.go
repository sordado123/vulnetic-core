package config

import "testing"

func TestPilotEmailAllowlist(t *testing.T) {
	t.Setenv("VULNETIC_SIGNUP_ALLOWLIST", " Alice@example.com, bob@example.com ")
	for email, want := range map[string]bool{"alice@example.com": true, " BOB@example.com ": true, "mallory@example.com": false, "alice@example.com.evil": false, "": false} {
		if got := PilotEmailAllowed(email); got != want {
			t.Errorf("%q: got %v want %v", email, got, want)
		}
	}
}
