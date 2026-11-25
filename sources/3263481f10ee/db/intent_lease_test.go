package db

import "testing"

func TestIntentClaimFencesExpiredWorker(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id, err := d.CreateExploration("lease-fixture", "synthetic claim fencing")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, id)
	s := d.Exploration(id)
	intent, err := s.AddIntent(map[string]any{"summary": "fixture"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.ClaimIntentWithLease(intent, "first", "open")
	if err != nil || old == "" {
		t.Fatal("claim failed", err)
	}
	if _, err = d.Exec(`UPDATE exploration_nodes SET last_heartbeat_at=now()-interval '2 minutes' WHERE id=$1`, intent); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HeartbeatIntent(intent, old); err != nil || ok {
		t.Fatal("expired claim revived", err)
	}
	if n, err := s.ResetRunningIntents(); err != nil || n != 1 {
		t.Fatal("expired claim not recovered", err)
	}
	current, err := s.ClaimIntentWithLease(intent, "second", "open")
	if err != nil || current == "" || current == old {
		t.Fatal("claim was not fenced", err)
	}
	if ok, err := s.SettleIntent(intent, old, "done", ""); err != nil || ok {
		t.Fatal("stale worker overwrote current state", err)
	}
	if ok, err := s.SettleIntent(intent, current, "done", ""); err != nil || !ok {
		t.Fatal("current worker could not finish", err)
	}
}
