package operatorinput

import (
	"strings"
	"testing"
	"time"
)

func TestScopedInputAndExpiry(t *testing.T) {
	s := &Store{}
	defer s.Close()
	scope := Scope{AccountID: 1, TaskID: 18, ExecutorID: 13}
	ref, expires, err := s.Put(scope, "654321", []string{"6543"})
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []Scope{{AccountID: 2, TaskID: 18, ExecutorID: 13}, {AccountID: 1, TaskID: 19, ExecutorID: 13}, {AccountID: 1, TaskID: 18, ExecutorID: 14}} {
		if _, err = s.Environment(other, ref); err == nil {
			t.Fatal("cross-owner input accepted")
		}
	}
	env, err := s.Environment(scope, ref)
	if err != nil || len(env) != 1 || env[0] != ref+"=654321" {
		t.Fatal("input unavailable", err)
	}
	if s.Redact(1, 18, 0, "code 654321") != "code [REDACTED]" {
		t.Fatal("input leaked into output")
	}
	masked, err := s.RedactJSON(1, 18, 0, []byte(`{"id":654321,"text":"code 654321","large":9007199254740993}`))
	if err != nil || !strings.Contains(string(masked), `"id":654321`) || !strings.Contains(string(masked), `9007199254740993`) || strings.Contains(string(masked), `code 654321`) {
		t.Fatal("invalid JSON redaction", err)
	}
	if _, err = s.RedactJSON(1, 18, 0, []byte(`{} {}`)); err == nil {
		t.Fatal("trailing proof JSON accepted")
	}
	if s.entries[ref].expires != expires {
		t.Fatal("reading extended expiry")
	}
	s.entries[ref].expires = time.Now().Add(-time.Second)
	if _, err = s.Environment(scope, ref); err == nil {
		t.Fatal("expired input accepted")
	}
	if strings.Contains(s.Redact(1, 18, 0, "654321"), "654321") {
		t.Fatal("late command output leaked")
	}
	conversation := Scope{AccountID: 1, TaskID: 18, ConversationID: 7, ExecutorID: 13}
	chatRef, _, err := s.Put(conversation, "fixture-chat-only", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Environment(scope, chatRef); err == nil {
		t.Fatal("chat input exposed to a task worker")
	}
	if _, err = s.Environment(conversation, chatRef); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = s.Environment(conversation, chatRef); err == nil {
		t.Fatal("input survived a cleared store")
	}
}

func TestSessionScopeAndNormalization(t *testing.T) {
	spec := Spec{Type: "session", TargetURL: "https://account.example.org/login"}
	value, masks, err := Prepare(spec, `{"cookies":[{"name":"session","value":"fixture-session-only","domain":".example.org","httpOnly":true}]}`)
	if err != nil || !strings.Contains(value, `"httpOnly":true`) || !strings.Contains(value, `"domain":".example.org"`) || len(masks) != 1 {
		t.Fatal("valid session rejected", err)
	}
	for _, bad := range []string{`[{"name":"session","value":"fixture","domain":"other.example.net"}]`, `[{"name":"session","value":"fixture","domain":"org"}]`, `{"origin":"https://other.example.net","cookies":[{"name":"session","value":"fixture"}]}`} {
		if _, _, err = Prepare(spec, bad); err == nil {
			t.Fatal("cross-site session accepted")
		}
	}
	if _, _, err = Prepare(Spec{Type: "one_time_code", TargetURL: "https://vulnetic.site"}, "654321"); err == nil {
		t.Fatal("protected platform accepted")
	}
	for _, bad := range []string{
		`{"origin":"http://account.example.org","cookies":[{"name":"s","value":"fixture"}]}`,
		`[{"name":"s","value":"fixture","expires":1}]`,
		`[{"name":"s","value":"fixture","path":"relative"}]`,
	} {
		if _, _, err = Prepare(spec, bad); err == nil {
			t.Fatal("invalid session accepted")
		}
	}
	if err := (&Spec{Type: "one_time_code"}).Validate(); err == nil {
		t.Fatal("code without service accepted")
	}
}
