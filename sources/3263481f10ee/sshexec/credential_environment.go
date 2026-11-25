package sshexec

import (
	"errors"
	"regexp"
	"strings"
)

var credentialVariable = regexp.MustCompile(`VULNETIC_CRED_[1-9][0-9]*_PASSWORD`)

// The authenticated gateway receives already-resolved environment entries; it has no vault.
func (l *LazyExecutor) commandEnvironment(command string, env []string) ([]string, error) {
	if strings.Contains(command, "{{cred:") {
		return nil, errors.New("use the password_env returned by the credential tool, not legacy placeholders")
	}
	if l.SecretResolver != nil {
		resolved, err := l.SecretResolver(command)
		if err != nil {
			return nil, err
		}
		env = append(append([]string{}, env...), resolved...)
	}
	provided := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			provided[key] = value
		}
	}
	for _, name := range credentialVariable.FindAllString(command, -1) {
		if value := provided[name]; value == "" || strings.ContainsRune(value, 0) {
			return nil, errors.New("requested credential is unavailable in this task or chat; list its credentials first")
		}
	}
	return env, nil
}
