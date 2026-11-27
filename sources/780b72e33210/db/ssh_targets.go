package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/sordado123/vulnetic/vault"
)

// SSH target connection states (ssh_targets.status).
const (
	SSHTargetPending  = "pending"
	SSHTargetVerified = "verified"
	SSHTargetFailed   = "failed"
)

// ErrSSHTargetNotFound indicates the target does not exist, or does not
// belong to the account asking for it.
var ErrSSHTargetNotFound = errors.New("ssh target not found")

// SSHTarget is one of an account's own VPS, reached over SSH (Fase B, Modo
// A). EncryptedPrivateKey/PrivateKeyNonce are never serialized to the UI —
// only sshexec decrypts them, and only to open a connection.
type SSHTarget struct {
	Transport           string          `json:"transport"`
	AgentExpiresAt      *time.Time      `json:"agent_expires_at,omitempty"`
	AgentConnected      bool            `json:"agent_connected"`
	Preflight           json.RawMessage `json:"preflight,omitempty"`
	HostKey             string          `json:"host_key"`
	ID                  int64           `json:"id"`
	AccountID           int64           `json:"-"`
	Name                string          `json:"name"`
	Host                string          `json:"host"`
	Port                int             `json:"port"`
	Username            string          `json:"username"`
	EncryptedPrivateKey []byte          `json:"-"`
	PrivateKeyNonce     []byte          `json:"-"`
	PublicKeyOpenSSH    string          `json:"public_key_openssh"`
	Fingerprint         string          `json:"fingerprint"`
	Status              string          `json:"status"`
	LastError           string          `json:"last_error,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	VerifiedAt          *time.Time      `json:"verified_at,omitempty"`
}

const sshTargetCols = `id, account_id, name, host, port, username, encrypted_private_key, private_key_nonce, public_key_openssh, fingerprint, status, last_error, created_at, updated_at, verified_at, host_key,preflight,transport,agent_expires_at`

func (t *SSHTarget) OperatingSystem() string {
	var result struct {
		OS string `json:"os"`
	}
	_ = json.Unmarshal(t.Preflight, &result)
	if result.OS == "windows" {
		return "windows"
	}
	return "linux"
}

func scanSSHTarget(sc interface{ Scan(...any) error }) (*SSHTarget, error) {
	var t SSHTarget
	if err := sc.Scan(&t.ID, &t.AccountID, &t.Name, &t.Host, &t.Port, &t.Username,
		&t.EncryptedPrivateKey, &t.PrivateKeyNonce, &t.PublicKeyOpenSSH, &t.Fingerprint,
		&t.Status, &t.LastError, &t.CreatedAt, &t.UpdatedAt, &t.VerifiedAt, &t.HostKey, &t.Preflight, &t.Transport, &t.AgentExpiresAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (d *DB) SaveSSHPreflight(accountID, id int64, result json.RawMessage) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	_, err := d.Exec(`UPDATE ssh_targets SET preflight=$3 WHERE account_id=$1 AND id=$2`, accountID, id, result)
	return err
}

func (d *DB) ConfirmSSHHostKey(accountID, id int64, key string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	result, err := d.Exec(`UPDATE ssh_targets SET host_key=$3,status='pending',verified_at=NULL WHERE id=$1 AND account_id=$2`, id, accountID, key)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if n == 0 {
		return ErrSSHTargetNotFound
	}
	return err
}

// ListSSHTargets returns an account's own targets, newest first.
func (d *DB) ListSSHTargets(accountID int64) ([]*SSHTarget, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	rows, err := d.Query(`SELECT `+sshTargetCols+` FROM ssh_targets WHERE account_id=$1 ORDER BY id DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SSHTarget{}
	for rows.Next() {
		t, err := scanSSHTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetSSHTarget fetches one target, scoped to accountID — a cross-account id
// returns ErrSSHTargetNotFound, not another account's row.
func (d *DB) GetSSHTarget(accountID, id int64) (*SSHTarget, error) {
	return d.GetSSHTargetContext(context.Background(), accountID, id)
}

func (d *DB) GetSSHTargetContext(ctx context.Context, accountID, id int64) (*SSHTarget, error) {
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) {
		return nil, ErrSSHTargetNotFound
	}
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	t, err := scanSSHTarget(d.QueryRowContext(ctx, `SELECT `+sshTargetCols+` FROM ssh_targets WHERE id=$1 AND account_id=$2`, id, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSSHTargetNotFound
	}
	return t, err
}

// CreateSSHTarget inserts a new target. The caller (server/ssh_targets_api.go)
// has already generated the keypair (sshexec.GenerateKeypair) and encrypted
// the private key (vault.Seal) under the account's DEK — this layer only
// persists the result.
func (d *DB) CreateSSHTarget(accountID int64, name, host string, port int, username string, encryptedPrivateKey, privateKeyNonce []byte, publicKeyOpenSSH, fingerprint string) (*SSHTarget, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	return scanSSHTarget(d.QueryRow(`
INSERT INTO ssh_targets(account_id, name, host, port, username, encrypted_private_key, private_key_nonce, public_key_openssh, fingerprint)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING `+sshTargetCols,
		accountID, name, host, port, username, encryptedPrivateKey, privateKeyNonce, publicKeyOpenSSH, fingerprint))
}

// DeleteSSHTarget removes a target and clears task/conversation bindings.
// SaaS execution stays blocked until an owned, ready executor is assigned.
// Scoped to accountID; returns ErrSSHTargetNotFound on a cross-account id.
func (d *DB) DeleteSSHTarget(accountID, id int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	res, err := d.Exec(`DELETE FROM ssh_targets WHERE id=$1 AND account_id=$2`, id, accountID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSSHTargetNotFound
	}
	return nil
}

// UpdateSSHTargetHealth records the outcome of one connection attempt —
// same shape as config.go's UpdateMCPHealth for MCP servers.
func (d *DB) UpdateSSHTargetHealth(accountID, id int64, ok bool, errMsg string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if ok {
		_, err := d.Exec(`UPDATE ssh_targets SET status=$3, last_error='', verified_at=now() WHERE id=$1 AND account_id=$2`,
			id, accountID, SSHTargetVerified)
		return err
	}
	_, err := d.Exec(`UPDATE ssh_targets SET status=$3, last_error=$4 WHERE id=$1 AND account_id=$2`,
		id, accountID, SSHTargetFailed, errMsg)
	return err
}

// GetOrCreateAccountDEK returns the account's plaintext data-encryption key,
// unwrapping the one already stored under kek (the server-wide master key,
// see vault.LoadOrCreateMasterKey) or generating and wrapping a fresh one on
// first use. Concurrent first-use races are resolved by re-reading after an
// ON CONFLICT DO NOTHING insert, so two simultaneous callers always agree on
// the same DEK rather than one silently encrypting under a DEK that was not
// the one actually persisted.
func (d *DB) GetOrCreateAccountDEK(accountID int64, kek []byte) ([]byte, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	wrapped, nonce, err := d.getAccountWrappedDEK(accountID)
	if err == nil {
		return vault.Open(kek, vault.Sealed{Nonce: nonce, Ciphertext: wrapped})
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	dek, err := vault.NewDEK()
	if err != nil {
		return nil, err
	}
	sealed, err := vault.Seal(kek, dek)
	if err != nil {
		return nil, err
	}
	if _, err := d.Exec(`INSERT INTO account_vault_keys(account_id, wrapped_dek, dek_nonce) VALUES ($1,$2,$3)
ON CONFLICT (account_id) DO NOTHING`, accountID, sealed.Ciphertext, sealed.Nonce); err != nil {
		return nil, err
	}
	wrapped, nonce, err = d.getAccountWrappedDEK(accountID)
	if err != nil {
		return nil, err
	}
	return vault.Open(kek, vault.Sealed{Nonce: nonce, Ciphertext: wrapped})
}

func (d *DB) getAccountWrappedDEK(accountID int64) (wrapped, nonce []byte, err error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	err = d.QueryRow(`SELECT wrapped_dek, dek_nonce FROM account_vault_keys WHERE account_id=$1`, accountID).Scan(&wrapped, &nonce)
	return wrapped, nonce, err
}
