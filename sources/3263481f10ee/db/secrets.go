package db

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/vault"
	"strings"
)

const secretPrefix = "vault:v1:"
const SecretMask = "********"

func (d *DB) ConfigureVault(key []byte, encrypt bool) {
	d.secretKey = append([]byte(nil), key...)
	d.encryptSecrets = encrypt
	d.accountKey = func(id int64) ([]byte, error) { return d.GetOrCreateAccountDEK(id, d.secretKey) }
}

func (d *DB) ShareVaultFrom(owner *DB) {
	d.secretKey = owner.secretKey
	d.encryptSecrets = owner.encryptSecrets
	d.accountKey = owner.accountKey
	d.transientRedactor = owner.transientRedactor
}

func (d *DB) ConfigureTransientRedactor(redact func(int64, int64, int64, string) string) {
	d.transientRedactor = redact
}

func (d *DB) sealSecret(accountID int64, value string) (string, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if value == "" || !d.encryptSecrets {
		return value, nil
	}
	if len(d.secretKey) != 32 || accountID <= 0 {
		return "", fmt.Errorf("vault is unavailable")
	}
	if d.accountKey == nil {
		return "", fmt.Errorf("vault is unavailable")
	}
	dek, err := d.accountKey(accountID)
	if err != nil {
		return "", fmt.Errorf("vault: account key unavailable")
	}
	sealed, err := vault.Seal(dek, []byte(value))
	if err != nil {
		return "", err
	}
	return secretPrefix + base64.RawStdEncoding.EncodeToString(sealed.Nonce) + ":" + base64.RawStdEncoding.EncodeToString(sealed.Ciphertext), nil
}

func (d *DB) openSecret(accountID int64, value string) (string, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if !strings.HasPrefix(value, secretPrefix) {
		return value, nil
	}
	if len(d.secretKey) != 32 {
		return "", fmt.Errorf("vault is unavailable")
	}
	parts := strings.Split(strings.TrimPrefix(value, secretPrefix), ":")
	if len(parts) != 2 {
		return "", vault.ErrInvalidSealed
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", vault.ErrInvalidSealed
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", vault.ErrInvalidSealed
	}
	if d.accountKey == nil {
		return "", fmt.Errorf("vault is unavailable")
	}
	dek, err := d.accountKey(accountID)
	if err != nil {
		return "", fmt.Errorf("vault: account key unavailable")
	}
	plain, err := vault.Open(dek, vault.Sealed{Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return "", fmt.Errorf("vault: secret authentication failed")
	}
	return string(plain), nil
}

func (d *DB) sealJSON(accountID int64, value json.RawMessage) (json.RawMessage, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if !d.encryptSecrets || len(value) == 0 {
		return value, nil
	}
	sealed, err := d.sealSecret(accountID, string(value))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"__vulnetic_vault": sealed})
}
func (d *DB) openJSON(accountID int64, value json.RawMessage) (json.RawMessage, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(value, &wrapper) != nil {
		return value, nil
	}
	raw, ok := wrapper["__vulnetic_vault"]
	if !ok || len(wrapper) != 1 {
		return value, nil
	}
	var sealed string
	if json.Unmarshal(raw, &sealed) != nil {
		return nil, vault.ErrInvalidSealed
	}
	if !strings.HasPrefix(sealed, "vault:v1:") {
		return value, nil
	}
	plain, err := d.openSecret(accountID, sealed)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(plain), nil
}

func (d *DB) openProfile(p *LLMProfile) error {
	for _, field := range []*string{&p.APIKey, &p.BaseURL, &p.Proxy} {
		value, err := d.openSecret(p.AccountID, *field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func (d *DB) openMCP(m *MCPServer) error {
	var err error
	if m.Command, err = d.openSecret(m.AccountID, m.Command); err != nil {
		return err
	}
	if m.URL, err = d.openSecret(m.AccountID, m.URL); err != nil {
		return err
	}
	if m.Args, err = d.openJSON(m.AccountID, m.Args); err != nil {
		return err
	}
	m.Env, err = d.openJSON(m.AccountID, m.Env)
	return err
}

func preserveMaskedMap(value, previous json.RawMessage) json.RawMessage {
	var current, old map[string]json.RawMessage
	if json.Unmarshal(value, &current) != nil || json.Unmarshal(previous, &old) != nil {
		return value
	}
	for key, raw := range current {
		var text string
		if json.Unmarshal(raw, &text) == nil && text == SecretMask {
			if saved, ok := old[key]; ok {
				current[key] = saved
			}
		}
	}
	result, err := json.Marshal(current)
	if err != nil {
		return value
	}
	return result
}

func (m *MCPServer) Masked() *MCPServer {
	copy := *m
	if copy.Command != "" {
		copy.Command = SecretMask
	}
	if copy.URL != "" {
		copy.URL = SecretMask
	}
	var args []string
	if json.Unmarshal(copy.Args, &args) == nil && len(args) > 0 {
		copy.Args = json.RawMessage(`["********"]`)
	}
	var env map[string]string
	if json.Unmarshal(copy.Env, &env) == nil {
		for key, value := range env {
			if value != "" {
				env[key] = SecretMask
			}
		}
		copy.Env, _ = json.Marshal(env)
	}
	return &copy
}
