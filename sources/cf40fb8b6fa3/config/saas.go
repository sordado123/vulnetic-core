package config

import (
	"net/mail"
	"os"
	"strings"
)

// SaaSMode enables the restrictions required for a shared, customer-facing install.
func SaaSMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("VULNETIC_SAAS_MODE")), "true")
}

func PilotEmailAllowed(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	for _, allowed := range strings.Split(os.Getenv("VULNETIC_SIGNUP_ALLOWLIST"), ",") {
		if email == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

// PublicSignup is operator-controlled; an unset or invalid flag keeps invite-only admission.
func PublicSignup() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("VULNETIC_PUBLIC_SIGNUP")), "true")
}

func SignupEmailAllowed(email string) bool {
	if !PublicSignup() {
		return PilotEmailAllowed(email)
	}
	email = strings.TrimSpace(email)
	if len(email) > 254 {
		return false
	}
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}
