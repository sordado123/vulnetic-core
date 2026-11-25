// Package operatorinput holds scoped, short-lived human input without persisting its value.
package operatorinput

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const Lifetime = 15 * time.Minute
const MaxValueBytes = 32 << 10

var ErrUnavailable = errors.New("operator input expired, belongs to another execution, or was lost on restart; ask the user again")
var referenceRE = regexp.MustCompile(`VULNETIC_INPUT_[a-f0-9]{32}_VALUE`)

type Scope struct{ AccountID, TaskID, ConversationID, ExecutorID int64 }
type entry struct {
	scope   Scope
	value   string
	masks   []string
	expires time.Time
	timer   *time.Timer
}
type Store struct {
	mu      sync.Mutex
	entries map[string]*entry
}

func (s *Store) Put(scope Scope, value string, masks []string) (string, time.Time, error) {
	if scope.AccountID <= 0 || (scope.TaskID <= 0 && scope.ConversationID <= 0) || scope.ExecutorID <= 0 || value == "" || len(value) > MaxValueBytes || strings.ContainsRune(value, 0) {
		return "", time.Time{}, errors.New("invalid sensitive input")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", time.Time{}, err
	}
	ref := "VULNETIC_INPUT_" + hex.EncodeToString(random[:]) + "_VALUE"
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = map[string]*entry{}
	}
	owned := 0
	for _, e := range s.entries {
		if e.scope.AccountID == scope.AccountID {
			owned++
		}
	}
	if owned >= 128 || len(s.entries) >= 4096 {
		return "", time.Time{}, errors.New("sensitive input capacity reached")
	}
	e := &entry{scope: scope, value: value, masks: append([]string{value}, masks...), expires: time.Now().Add(Lifetime)}
	s.entries[ref] = e
	// Retain a RAM-only redaction grace period for output from already-started commands.
	e.timer = time.AfterFunc(Lifetime+24*time.Hour, func() { s.Remove(ref) })
	return ref, e.expires, nil
}

func (s *Store) Remove(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[ref]; e != nil {
		e.timer.Stop()
		delete(s.entries, ref)
	}
}
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, e := range s.entries {
		e.timer.Stop()
		delete(s.entries, ref)
	}
}

func (s *Store) Environment(scope Scope, command string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	env := []string{}
	seen := map[string]bool{}
	for _, ref := range referenceRE.FindAllString(command, -1) {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		e := s.entries[ref]
		if e == nil || e.scope.AccountID != scope.AccountID || e.scope.ExecutorID != scope.ExecutorID || !time.Now().Before(e.expires) {
			return nil, ErrUnavailable
		}
		if e.scope.ConversationID > 0 {
			if scope.ConversationID != e.scope.ConversationID {
				return nil, ErrUnavailable
			}
		} else if e.scope.TaskID <= 0 || e.scope.TaskID != scope.TaskID {
			return nil, ErrUnavailable
		}
		env = append(env, ref+"="+e.value)
	}
	return env, nil
}

func (s *Store) Redact(accountID, taskID, conversationID int64, text string) string {
	s.mu.Lock()
	values := map[string]bool{}
	for _, e := range s.entries {
		if e.scope.AccountID != accountID || !((taskID == 0 && conversationID == 0) || (taskID > 0 && e.scope.TaskID == taskID) || (conversationID > 0 && e.scope.ConversationID == conversationID)) {
			continue
		}
		for _, value := range e.masks {
			if value != "" {
				values[value] = true
			}
		}
	}
	s.mu.Unlock()
	if len(values) == 0 {
		return text
	}
	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	pairs := make([]string, 0, 2*len(ordered))
	for _, value := range ordered {
		pairs = append(pairs, value, "[REDACTED]")
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

func (s *Store) RedactJSON(accountID, taskID, conversationID int64, raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid trailing proof JSON")
	}
	var visit func(any) any
	visit = func(v any) any {
		switch x := v.(type) {
		case string:
			return s.Redact(accountID, taskID, conversationID, x)
		case map[string]any:
			for k, item := range x {
				x[k] = visit(item)
			}
		case []any:
			for i, item := range x {
				x[i] = visit(item)
			}
		}
		return v
	}
	return json.Marshal(visit(value))
}
