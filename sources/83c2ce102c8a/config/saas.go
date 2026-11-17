package config

import (
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
