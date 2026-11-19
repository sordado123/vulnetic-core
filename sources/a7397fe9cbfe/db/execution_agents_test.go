package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"testing"
	"time"
)

func TestBetaAgentEnrollmentLeaseIsolation(t *testing.T) {
	d := betaTestDB(t)
	ctx := context.Background()
	a := newTestAccount(t, d, "agent-a")
	b := newTestAccount(t, d, "agent-b")
	join := bytes.Repeat([]byte{1}, 32)
	for _, duration := range []int{0, 299, 604801} {
		if _, err := d.ForAccount(a).CreateExecutionAgent(ctx, a, "invalid lifetime", duration, join, nil, nil, "", ""); !errors.Is(err, ErrAgentLease) {
			t.Fatal("unbounded agent lifetime accepted")
		}
	}
	runtimeHash := bytes.Repeat([]byte{2}, 32)
	target, err := d.ForAccount(a).CreateExecutionAgent(ctx, a, "Temporary VPS", 300, join, []byte("encrypted"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if target.Transport != "agent" || target.AgentExpiresAt != nil {
		t.Fatal("unconnected agent appeared live")
	}
	if _, err = d.ForAccount(b).CreateExecutionAgent(ctx, a, "foreign", 300, join, nil, nil, "", ""); err == nil {
		t.Fatal("foreign owner accepted")
	}
	if err = d.ForAccount(b).RenewExecutionAgent(ctx, b, target.ID, 300, join); !errors.Is(err, ErrSSHTargetNotFound) {
		t.Fatalf("foreign renewal: %v", err)
	}
	enrolled, lifetime, err := d.RedeemAgentEnrollment(ctx, join, runtimeHash, "host-key", "fixture")
	if err != nil || lifetime != 300 || !enrolled.AgentLeaseCurrent(time.Now()) {
		t.Fatalf("enrollment: %v", err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, join, bytes.Repeat([]byte{3}, 32), "changed", "fixture"); !errors.Is(err, ErrAgentLease) {
		t.Fatal("enrollment token was reusable")
	}
	account, id, err := d.AgentIdentity(ctx, runtimeHash)
	if err != nil || account != a || id != target.ID {
		t.Fatalf("identity mismatch: %v", err)
	}
	if _, _, err = d.ForAccount(a).AgentIdentity(ctx, runtimeHash); !errors.Is(err, ErrAgentLease) {
		t.Fatal("public-token lookup exposed to scoped repositories")
	}
	if _, err = d.Exec(`UPDATE accounts SET blocked=true WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.AgentIdentity(ctx, runtimeHash); !errors.Is(err, ErrAgentLease) {
		t.Fatal("blocked account retained agent access")
	}
	if _, err = d.Exec(`UPDATE accounts SET blocked=false WHERE id=$1`, a); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.AgentIdentity(ctx, runtimeHash); !errors.Is(err, ErrAgentLease) {
		t.Fatal("unblocking resurrected an old agent credential")
	}
	replacement := bytes.Repeat([]byte{6}, 32)
	if err = d.ForAccount(a).RenewExecutionAgent(ctx, a, target.ID, 300, replacement); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, replacement, runtimeHash, "host-key", "fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE ssh_targets SET agent_expires_at=now()-interval '1 second' WHERE id=$1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.AgentIdentity(ctx, runtimeHash); !errors.Is(err, ErrAgentLease) {
		t.Fatal("expired lease retained access")
	}
	newJoin := bytes.Repeat([]byte{4}, 32)
	if err = d.ForAccount(a).RenewExecutionAgent(ctx, a, target.ID, 600, newJoin); err != nil {
		t.Fatal(err)
	}
	if revoked, e := d.RevokeAgentConnection(ctx, a, target.ID, runtimeHash); e != nil || revoked {
		t.Fatal("stale connection changed fresh enrollment")
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, newJoin, runtimeHash, "new-host", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err = d.ForAccount(a).RevokeExecutionAgent(ctx, a, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.AgentIdentity(ctx, runtimeHash); !errors.Is(err, ErrAgentLease) {
		t.Fatal("revoked lease retained access")
	}
	join = bytes.Repeat([]byte{5}, 32)
	if err = d.ForAccount(a).RenewExecutionAgent(ctx, a, target.ID, 300, join); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE execution_agents SET join_expires_at=now()-interval '1 second' WHERE target_id=$1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.RedeemAgentEnrollment(ctx, join, runtimeHash, "host", "fixture"); !errors.Is(err, ErrAgentLease) {
		t.Fatal("expired installation command accepted")
	}
}

func TestBetaAgentRLS(t *testing.T) {
	if config.PostgresAppPassword() == "" {
		t.Setenv("VULNETIC_PG_APP_PASSWORD", rlsTestAppPassword)
	}
	d := betaTestDB(t)
	a := newTestAccount(t, d, "agent-rls-a")
	b := newTestAccount(t, d, "agent-rls-b")
	_, err := d.CreateExecutionAgent(context.Background(), a, "private", 300, bytes.Repeat([]byte{9}, 32), []byte("key"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	dsn, err := config.PostgresAppDSN()
	if err != nil || dsn == "" {
		t.Fatal("RLS app pool is required")
	}
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	assertUnscopedCountAsAccount(t, pool, "execution_agents", b, 0)
	assertUnscopedCountAsAccount(t, pool, "execution_agents", a, 1)
}

func TestBetaAgentExtendedLifetimes(t *testing.T) {
	d := betaTestDB(t)
	ctx := t.Context()
	account := newTestAccount(t, d, "extended-agent")
	for _, seconds := range []int{10800, 86400, 259200, 604800} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			join := bytes.Repeat([]byte{byte(seconds / 3600)}, 32)
			target, err := d.ForAccount(account).CreateExecutionAgent(ctx, account, "Extended VPS", seconds, join, []byte("encrypted"), []byte("nonce"), "public", "fingerprint")
			if err != nil {
				t.Fatal(err)
			}
			runtime := bytes.Repeat([]byte{byte(seconds/3600 + 1)}, 32)
			started := time.Now()
			enrolled, lifetime, err := d.RedeemAgentEnrollment(ctx, join, runtime, "host-key", "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if lifetime != seconds || enrolled.AgentExpiresAt == nil || (enrolled.AgentExpiresAt.Sub(started) < time.Duration(seconds)*time.Second-5*time.Second || enrolled.AgentExpiresAt.Sub(started) > time.Duration(seconds)*time.Second+5*time.Second) {
				t.Fatal("lease deadline does not match the chosen duration")
			}
			replacement := bytes.Repeat([]byte{byte(seconds/3600 + 2)}, 32)
			if err = d.ForAccount(account).RenewExecutionAgent(ctx, account, target.ID, seconds, replacement); err != nil {
				t.Fatal(err)
			}
			if _, _, err = d.AgentIdentity(ctx, runtime); !errors.Is(err, ErrAgentLease) {
				t.Fatal("renewal left old access valid")
			}
			if err = d.ForAccount(account).RenewExecutionAgent(ctx, account, target.ID, 604801, replacement); !errors.Is(err, ErrAgentLease) {
				t.Fatal("renewal accepted a lease over 7 days")
			}
		})
	}
}

func TestBetaAgentLeaseMigrationPreservesExistingEnrollment(t *testing.T) {
	d := betaTestDB(t)
	account := newTestAccount(t, d, "lease-migration")
	target, err := d.CreateExecutionAgent(t.Context(), account, "Existing VPS", 300, bytes.Repeat([]byte{244}, 32), []byte("key"), []byte("nonce"), "public", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM beta_migrations WHERE version=15;
 ALTER TABLE execution_agents DROP CONSTRAINT execution_agents_lifetime_seconds_check;
 ALTER TABLE execution_agents ADD CONSTRAINT execution_agents_lifetime_seconds_check CHECK(lifetime_seconds BETWEEN 300 AND 86400);`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = tx.Exec(betaSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	var duration int
	if err = tx.QueryRow(`SELECT lifetime_seconds FROM execution_agents WHERE target_id=$1 AND account_id=$2`, target.ID, account).Scan(&duration); err != nil || duration != 300 {
		t.Fatal("migration changed an existing enrollment", err)
	}
	if _, err = tx.Exec(`UPDATE execution_agents SET lifetime_seconds=604800 WHERE target_id=$1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE execution_agents SET lifetime_seconds=604801 WHERE target_id=$1`, target.ID); err == nil {
		t.Fatal("database accepted a lease over 7 days")
	}
}
