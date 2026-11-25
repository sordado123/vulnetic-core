package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrAgentLease = errors.New("agent enrollment or lease is invalid, expired or revoked")

func agentOS(values []string) (string, bool) {
	platform := "linux"
	if len(values) > 0 && values[0] != "" {
		platform = values[0]
	}
	return platform, platform == "linux" || platform == "windows"
}

func (d *DB) CreateExecutionAgent(ctx context.Context, accountID int64, name string, lifetime int, joinHash []byte, encryptedKey, nonce []byte, publicKey, fingerprint string, platforms ...string) (*SSHTarget, error) {
	platform, ok := agentOS(platforms)
	if !ok {
		return nil, ErrAgentLease
	}
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) || lifetime < 300 || lifetime > 604800 || len(joinHash) != 32 {
		return nil, ErrAgentLease
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	target, err := scanSSHTarget(tx.QueryRowContext(ctx, `INSERT INTO ssh_targets(account_id,name,host,port,username,encrypted_private_key,private_key_nonce,public_key_openssh,fingerprint,transport,preflight)
 VALUES($1,$2,'outbound-agent',22,'pending',$3,$4,$5,$6,'agent',jsonb_build_object('os',$7::text)) RETURNING `+sshTargetCols, accountID, name, encryptedKey, nonce, publicKey, fingerprint, platform))
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO execution_agents(target_id,account_id,join_hash,join_expires_at,lifetime_seconds,account_version)
 SELECT $1,$2,$3,now()+interval '5 minutes',$4,a.session_version FROM accounts a WHERE a.id=$2 AND NOT a.blocked`, target.ID, accountID, joinHash, lifetime)
	if err != nil {
		return nil, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return nil, ErrAgentLease
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return target, nil
}

func (d *DB) RenewExecutionAgent(ctx context.Context, accountID, targetID int64, lifetime int, joinHash []byte, platforms ...string) error {
	platform, ok := agentOS(platforms)
	if !ok {
		return ErrAgentLease
	}
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) || lifetime < 300 || lifetime > 604800 || len(joinHash) != 32 {
		return ErrAgentLease
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE execution_agents SET join_hash=$3,join_expires_at=now()+interval '5 minutes',lifetime_seconds=$4,runtime_hash=NULL,enrolled_at=NULL,revoked_at=NULL,account_version=(SELECT session_version FROM accounts WHERE id=$1 AND NOT blocked) WHERE account_id=$1 AND target_id=$2`, accountID, targetID, joinHash, lifetime)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSSHTargetNotFound
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssh_targets SET host_key='',agent_expires_at=NULL,status='pending',verified_at=NULL,preflight=jsonb_build_object('os',$3::text),last_error='' WHERE account_id=$1 AND id=$2 AND transport='agent'`, accountID, targetID, platform)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Enrollment is the only unauthenticated owner-pool lookup. Possession of a
// random, short-lived one-use token fixes the account and target in the database.
func (d *DB) RedeemAgentEnrollment(ctx context.Context, joinHash, runtimeHash []byte, hostKey, username string, platforms ...string) (*SSHTarget, int, error) {
	platform, ok := agentOS(platforms)
	if !ok {
		return nil, 0, ErrAgentLease
	}
	if d.hasAccount || len(joinHash) != 32 || len(runtimeHash) != 32 {
		return nil, 0, ErrAgentLease
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var accountID, targetID int64
	var lifetime int
	enrollmentQuery := `SELECT e.account_id,e.target_id,e.lifetime_seconds FROM execution_agents e JOIN accounts a ON a.id=e.account_id
 WHERE e.join_hash=$1 AND e.join_expires_at>now() AND e.enrolled_at IS NULL AND e.revoked_at IS NULL AND NOT a.blocked AND e.account_version=a.session_version FOR UPDATE OF e`
	if d.RuntimeOnly() {
		enrollmentQuery = `SELECT account_id,target_id,lifetime_seconds FROM public.vulnetic_agent_enrollment($1)`
	}
	err = tx.QueryRowContext(ctx, enrollmentQuery, joinHash).Scan(&accountID, &targetID, &lifetime)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrAgentLease
	}
	if err != nil {
		return nil, 0, err
	}
	if d.RuntimeOnly() {
		if err = setAccountGUC(tx, accountID); err != nil {
			return nil, 0, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE execution_agents SET join_hash=NULL,runtime_hash=$2,enrolled_at=now() WHERE target_id=$1`, targetID, runtimeHash)
	if err != nil {
		return nil, 0, err
	}
	target, err := scanSSHTarget(tx.QueryRowContext(ctx, `UPDATE ssh_targets SET host_key=$3,username=$4,status='pending',verified_at=NULL,preflight=jsonb_build_object('os',$6::text),last_error='',agent_expires_at=now()+make_interval(secs=>$5) WHERE account_id=$1 AND id=$2 AND transport='agent' RETURNING `+sshTargetCols, accountID, targetID, hostKey, username, lifetime, platform))
	if err != nil {
		return nil, 0, err
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, err
	}
	return target, lifetime, nil
}

func (d *DB) AgentIdentity(ctx context.Context, runtimeHash []byte) (int64, int64, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		return d.runtimeAgentIdentity(ctx, runtimeHash)
	}
	if d.hasAccount || len(runtimeHash) != 32 {
		return 0, 0, ErrAgentLease
	}
	var accountID, targetID int64
	err := d.QueryRowContext(ctx, `SELECT e.account_id,e.target_id FROM execution_agents e JOIN accounts a ON a.id=e.account_id JOIN ssh_targets t ON t.id=e.target_id
 WHERE e.runtime_hash=$1 AND e.revoked_at IS NULL AND NOT a.blocked AND e.account_version=a.session_version AND t.agent_expires_at>now()`, runtimeHash).Scan(&accountID, &targetID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrAgentLease
	}
	return accountID, targetID, err
}

func (d *DB) RevokeExecutionAgent(ctx context.Context, accountID, targetID int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) {
		return ErrAgentLease
	}
	result, err := d.ExecContext(ctx, `UPDATE execution_agents SET join_hash=NULL,runtime_hash=NULL,revoked_at=now() WHERE account_id=$1 AND target_id=$2`, accountID, targetID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSSHTargetNotFound
	}
	return nil
}

func (t *SSHTarget) AgentLeaseCurrent(now time.Time) bool {
	return t != nil && t.Transport == "agent" && t.AgentExpiresAt != nil && now.Before(*t.AgentExpiresAt)
}

// A stale connection must never revoke a freshly issued installation command.
func (d *DB) RevokeAgentConnection(ctx context.Context, accountID, targetID int64, runtimeHash []byte) (bool, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if d.hasAccount || len(runtimeHash) != 32 {
		return false, ErrAgentLease
	}
	result, err := d.ExecContext(ctx, `UPDATE execution_agents SET runtime_hash=NULL,revoked_at=now() WHERE account_id=$1 AND target_id=$2 AND runtime_hash=$3`, accountID, targetID, runtimeHash)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Beta runs one platform process. A restart requires fresh enrollment; leases
// are never restored into an unauthenticated in-memory connection registry.
func (d *DB) InvalidateActiveAgentLeases(ctx context.Context) error {
	if d.hasAccount {
		return ErrAgentLease
	}
	_, err := d.ExecContext(ctx, `UPDATE execution_agents SET runtime_hash=NULL,revoked_at=now() WHERE runtime_hash IS NOT NULL`)
	return err
}
