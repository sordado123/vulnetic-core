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

func TestPublicSignupAdmission(t *testing.T) {
	t.Setenv("VULNETIC_SIGNUP_ALLOWLIST", "invited@example.com")
	for _, flag := range []string{"", "false", "invalid"} {
		t.Setenv("VULNETIC_PUBLIC_SIGNUP", flag)
		if PublicSignup() || SignupEmailAllowed("new@example.com") || !SignupEmailAllowed("invited@example.com") {
			t.Fatalf("invite-only admission changed for flag %q", flag)
		}
	}
	t.Setenv("VULNETIC_PUBLIC_SIGNUP", " TRUE ")
	if !PublicSignup() {
		t.Fatal("public signup was not enabled")
	}
	for email, want := range map[string]bool{"new@example.com": true, " NEW@example.com ": true, "": false, "not-an-email": false, "Name <new@example.com>": false, "a@example.com\nother@example.com": false} {
		if got := SignupEmailAllowed(email); got != want {
			t.Errorf("%q allowed=%v want %v", email, got, want)
		}
	}
	t.Setenv("VULNETIC_PUBLIC_SIGNUP", "false")
	if SignupEmailAllowed("new@example.com") {
		t.Fatal("switching back to invitation mode failed")
	}
}
