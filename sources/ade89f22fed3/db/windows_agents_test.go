package db

import (
	"bytes"
	"context"
	"testing"
)

func TestBetaWindowsForegroundLeaseIsolation(t *testing.T) {
	d := betaTestDB(t)
	ctx := context.Background()
	a, b := newTestAccount(t, d, "terminal-a"), newTestAccount(t, d, "terminal-b")
	join, runtime := bytes.Repeat([]byte{81}, 32), bytes.Repeat([]byte{82}, 32)
	target, err := d.ForAccount(a).CreateExecutionAgent(ctx, a, "Terminal", 10800, join, []byte("sealed"), []byte("nonce"), "public", "fingerprint", "windows")
	if err != nil || target.OperatingSystem() != "windows" {
		t.Fatal("Windows choice was not persisted", err)
	}
	if _, err = d.ForAccount(b).CreateExecutionAgent(ctx, b, "Terminal", 10800, bytes.Repeat([]byte{83}, 32), []byte("sealed"), []byte("nonce"), "public", "fingerprint", "linux"); err != nil {
		t.Fatal("second account fixture failed", err)
	}
	if _, err = d.GetSSHTarget(b, target.ID); err == nil {
		t.Fatal("foreign target was exposed")
	}
	connected, lifetime, err := d.RedeemAgentEnrollment(ctx, join, runtime, "host-key", "vulnetic-terminal", "windows")
	if err != nil || connected.AccountID != a || connected.ID != target.ID || connected.OperatingSystem() != "windows" || lifetime != 10800 || connected.AgentExpiresAt == nil {
		t.Fatal("foreground enrollment lost owner, OS or lifetime", err)
	}
	for range 2 {
		account, id, e := d.AgentIdentity(ctx, runtime)
		if e != nil || account != a || id != target.ID {
			t.Fatal("reconnect identity changed", e)
		}
	}
	after, err := d.GetSSHTarget(a, target.ID)
	if err != nil || !after.AgentExpiresAt.Equal(*connected.AgentExpiresAt) {
		t.Fatal("reconnect renewed deadline", err)
	}
	if err = d.ForAccount(b).RevokeExecutionAgent(ctx, b, target.ID); err == nil {
		t.Fatal("foreign account revoked Windows authorization")
	}
	if err = d.ForAccount(a).RevokeExecutionAgent(ctx, a, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.AgentIdentity(ctx, runtime); err == nil {
		t.Fatal("revoked authorization remained usable")
	}
}
