// Package runstate holds execution metadata, never prompts or credentials.
package runstate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	ID                   string     `json:"id"`
	ConversationID       int64      `json:"conversation_id,omitempty"`
	TaskID               int64      `json:"task_id,omitempty"`
	ExecutorID           int64      `json:"executor_id,omitempty"`
	IntentID             int64      `json:"intent_id,omitempty"`
	Lane                 string     `json:"lane,omitempty"`
	Status               string     `json:"status"`
	Phase                string     `json:"phase"`
	PhaseAt              time.Time  `json:"phase_at"`
	StartedAt            time.Time  `json:"started_at"`
	FinishedAt           *time.Time `json:"finished_at,omitempty"`
	TokenLimit           int64      `json:"token_limit"`
	Tokens               int64      `json:"tokens"`
	Calls                int        `json:"calls"`
	Tools                int        `json:"tools"`
	CompletedTools       int        `json:"completed_tools"`
	FailedTools          int        `json:"failed_tools"`
	PendingTools         int        `json:"pending_tools"`
	Code                 string     `json:"code,omitempty"`
	Message              string     `json:"message,omitempty"`
	Recovery             string     `json:"recovery,omitempty"`
	Checkpoint           string     `json:"checkpoint,omitempty"`
	RecentTools          []string   `json:"recent_tools,omitempty"`
	PendingIDs           []string   `json:"pending_ids,omitempty"`
	DurationLimitSeconds int        `json:"duration_limit_seconds,omitempty"`
}
type State struct {
	mu            sync.Mutex
	snapshot      Snapshot
	save          func(Snapshot) error
	saveError     error
	terminalError error
	failures      map[[32]byte]time.Time
	dependencies  map[string]string
}
type key struct{}

func From(ctx context.Context) *State                    { s, _ := ctx.Value(key{}).(*State); return s }
func Bind(ctx context.Context, s *State) context.Context { return context.WithValue(ctx, key{}, s) }

// Zero denotes no platform token cap; usage remains recorded per execution.
func TokenLimit() int64 { return 0 }

func New(s Snapshot, save func(Snapshot) error) (*State, error) {
	now := time.Now().UTC()
	s.StartedAt = now
	s.PhaseAt = now
	s.Status = "running"
	s.Phase = "preflight"
	s.TokenLimit = TokenLimit()
	r := &State{snapshot: s, save: save, failures: map[[32]byte]time.Time{}, dependencies: map[string]string{}}
	if err := r.persist(); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *State) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snapshot
	out.RecentTools = append([]string(nil), out.RecentTools...)
	out.PendingIDs = append([]string(nil), out.PendingIDs...)
	return out
}
func (s *State) persist() error {
	if s.save != nil {
		if err := s.save(s.snapshot); err != nil {
			s.saveError = err
			return err
		}
	}
	return nil
}
func (s *State) Phase(phase string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.FinishedAt != nil || s.snapshot.Phase == phase {
		return
	}
	s.snapshot.Phase = phase
	s.snapshot.PhaseAt = time.Now().UTC()
	_ = s.persist()
}
func (s *State) LimitDuration(seconds int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.DurationLimitSeconds = seconds
	_ = s.persist()
}
func (s *State) BeforeCall() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.FinishedAt != nil {
		return errors.New("execution_closed: start a new execution before running tools")
	}
	if s.saveError != nil {
		return errors.New("execution_state_unavailable: unable to persist execution status")
	}
	return nil
}
func (s *State) AddUsage(input, output int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.Tokens += int64(max(0, input) + max(0, output))
	s.snapshot.Calls++
	_ = s.persist()
}
func fingerprint(name string, input []byte) [32]byte {
	var v any
	if json.Unmarshal(input, &v) == nil {
		input, _ = json.Marshal(v)
	}
	return sha256.Sum256(append([]byte(name+"\x00"), input...))
}
func (s *State) BeforeTool(name string, input []byte) error {
	if s == nil {
		return nil
	}
	if err := s.BeforeCall(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reason := s.dependencies[name]; reason != "" {
		return fmt.Errorf("prerequisite_unchanged: %s. Read the relevant context or change the prerequisite before retrying this operation", reason)
	}
	k := fingerprint(name, input)
	// shortcut: deterministic dependency failures cool down for one minute; configuration changes clear them immediately.
	if at, ok := s.failures[k]; ok && time.Since(at) < time.Minute {
		return errors.New("dependency_unchanged: this call already failed; change its prerequisites before retrying")
	}
	return nil
}
func (s *State) AfterTool(name string, input, result []byte, failed bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := fingerprint(name, input)
	if !failed {
		if name == "get_finding_review_context" || name == "list_task_execution_proofs" {
			delete(s.dependencies, "record_finding_evidence_review")
		}
		if name == "set_task_prerequisite" {
			clear(s.dependencies)
		}
		delete(s.failures, k)
		if strings.HasPrefix(name, "update_") || strings.HasPrefix(name, "create_") || strings.HasPrefix(name, "save_") {
			clear(s.failures)
		}
		return
	}
	t := strings.ToLower(string(result))
	if name == "record_finding_evidence_review" && (strings.Contains(t, "proof") || strings.Contains(t, "quotes") || strings.Contains(t, "finding_id")) {
		if s.dependencies == nil {
			s.dependencies = map[string]string{}
		}
		s.dependencies[name] = "evidence source required; call get_finding_review_context(finding_id) and select a positive proof_id or traffic_binding_id"
	}
	if strings.Contains(t, "only available inside a task") || strings.Contains(t, "not initialized") || strings.Contains(t, "missing required property") || strings.Contains(t, "policy_denied") || strings.Contains(t, "select a verified vps") {
		if len(s.failures) < 256 {
			s.failures[k] = time.Now()
		}
	}
}
func (s *State) Observe(kind string, failed bool) {
	if s == nil || (kind != "tool_use" && kind != "tool_result") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "tool_use":
		s.snapshot.Tools++
		s.snapshot.PendingTools++
	case "tool_result":
		s.snapshot.CompletedTools++
		s.snapshot.PendingTools = max(0, s.snapshot.PendingTools-1)
		if failed {
			s.snapshot.FailedTools++
		}
	}
	_ = s.persist()
}
func (s *State) ToolReference(kind, id, name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "tool_use":
		if len(s.snapshot.PendingIDs) < 128 {
			s.snapshot.PendingIDs = append(s.snapshot.PendingIDs, id)
		}
	case "tool_result":
		for i, v := range s.snapshot.PendingIDs {
			if v == id {
				s.snapshot.PendingIDs = append(s.snapshot.PendingIDs[:i], s.snapshot.PendingIDs[i+1:]...)
				break
			}
		}
		s.snapshot.RecentTools = append(s.snapshot.RecentTools, name)
		if len(s.snapshot.RecentTools) > 12 {
			s.snapshot.RecentTools = s.snapshot.RecentTools[len(s.snapshot.RecentTools)-12:]
		}
	}
}

func Classify(err error) (code, message, recovery string) {
	if err == nil {
		return "", "Execution completed.", "Review the recorded results before continuing."
	}
	t := strings.ToLower(err.Error())
	switch {
	case strings.Contains(t, "waiting_operator"):
		return "waiting_operator", "Waiting for operator input.", "Reply to the delivered question to continue. Other independent Workers can continue."
	case strings.Contains(t, "executor_expired"):
		return "executor_expired", "Executor access expired.", "Create a new authorization explicitly; the original access deadline is not renewed."
	case strings.Contains(t, "executor_revoked") || strings.Contains(t, "executor_closed"):
		return "executor_revoked", "This executor authorization or execution connection was closed.", "Check the executor authorization and start a new execution when access is valid."
	case strings.Contains(t, "gateway_unavailable") || strings.Contains(t, "gateway disconnected"):
		return "gateway_unavailable", "The executor gateway connection is unavailable.", "Wait for the authenticated connection to recover before starting another operation. Interrupted commands are not replayed."
	case strings.Contains(t, "executor_offline"):
		return "executor_offline", "The selected executor has not reconnected.", "Keep the agent terminal open and check its network connection. The original expiry still applies."
	case strings.Contains(t, "max_turns"):
		return "step_limit", "Execution reached its step limit.", "Review the checkpoint and continue only the unfinished steps."
	case strings.Contains(t, "token_budget_exceeded"):
		return "token_budget", "Execution reached its token budget.", "Review the checkpoint and start a narrower execution; existing evidence is preserved."
	case strings.Contains(t, "policy_denied") || strings.Contains(t, "execution_policy") || strings.Contains(t, "platform safety"):
		return "platform_policy", "Platform safety policy blocked this operation.", "Use an allowed target or operation; approval cannot override platform policy."
	case strings.Contains(t, "verified vps") || strings.Contains(t, "executor") || strings.Contains(t, "agent access") || strings.Contains(t, "vps changed"):
		return "executor_unavailable", "The selected executor is unavailable.", "Select or reconnect an authorized executor, then retry. Its expiry is not renewed automatically."
	case strings.Contains(t, "invalid schema") || strings.Contains(t, "invalid_function_parameters") || strings.Contains(t, "missing required property"):
		return "tool_schema", "A tool definition was rejected.", "Correct the tool configuration before retrying."
	case strings.Contains(t, "401") || strings.Contains(t, "invalid api key") || strings.Contains(t, "invalid_api_key") || strings.Contains(t, "authentication"):
		return "provider_auth", "The model provider rejected authentication.", "Check this account's model profile and key."
	case strings.Contains(t, "429") || strings.Contains(t, "rate limit") || strings.Contains(t, "rate_limit"):
		return "rate_limit", "The model provider limited requests.", "Wait before retrying or select another configured profile."
	case strings.Contains(t, "quota") || strings.Contains(t, "insufficient"):
		return "provider_quota", "The configured provider quota is unavailable.", "Check provider balance or choose another configured profile."
	case strings.Contains(t, "i/o timeout"):
		return "network_timeout", "The model or executor connection timed out.", "Check connectivity and retry only the unfinished work; this is not the execution time limit."
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(t, "timeout") || strings.Contains(t, "deadline"):
		return "timeout", "Execution reached its time limit.", "Review completed work and continue only the remaining steps."
	case errors.Is(err, context.Canceled) || strings.Contains(t, "cancelled") || strings.Contains(t, "stopped"):
		return "cancelled", "Execution was interrupted.", "Review the checkpoint before resuming; unfinished commands are not replayed automatically."
	case strings.Contains(t, "503") || strings.Contains(t, "502") || strings.Contains(t, "500") || strings.Contains(t, "server_error") || strings.Contains(t, "overloaded"):
		return "provider_unavailable", "The model provider is temporarily unavailable.", "Retry later or choose another configured profile."
	case strings.Contains(t, "network") || strings.Contains(t, "connection") || strings.Contains(t, "dial tcp"):
		return "network", "The model connection failed.", "Check connectivity and retry only the unfinished work."
	case strings.Contains(t, "context") && strings.Contains(t, "limit"):
		return "context_limit", "The model context limit was reached.", "Continue from the checkpoint with a narrower request."
	case strings.Contains(t, "invalid_request") || strings.Contains(t, "unsupported_parameter") || strings.Contains(t, "unsupported_value"):
		return "provider_request", "The model provider rejected the request.", "Review the model profile and the recorded provider error before retrying."
	case strings.Contains(t, "stream") || strings.Contains(t, "unexpected eof") || strings.Contains(t, "response.failed"):
		return "provider_stream", "The model stream was interrupted.", "Completed tool results remain recorded. Review the checkpoint and continue only unfinished work."
	default:
		return "dependency", "Execution could not finish.", "Review execution details and correct the unavailable prerequisite before retrying."
	}
}
func (s *State) Terminal(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.terminalError = err
}

func (s *State) WaitingForOperator() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalError != nil && strings.Contains(s.terminalError.Error(), "waiting_operator")
}

func (s *State) Finish(err error) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil || (s.terminalError != nil && strings.Contains(s.terminalError.Error(), "waiting_operator")) {
		err = s.terminalError
	}
	now := time.Now().UTC()
	s.snapshot.FinishedAt = &now
	s.snapshot.Phase = "finished"
	s.snapshot.PhaseAt = now
	s.snapshot.Status = "completed"
	if err != nil {
		s.snapshot.Status = "blocked"
	}
	if errors.Is(err, context.Canceled) {
		s.snapshot.Status = "interrupted"
	}
	s.snapshot.Code, s.snapshot.Message, s.snapshot.Recovery = Classify(err)
	if s.snapshot.Code == "waiting_operator" {
		s.snapshot.Status = "waiting_operator"
	}
	s.snapshot.Checkpoint = fmt.Sprintf("%d tool calls; %d returned (%d errors); %d have no returned result. %d model calls; %d tokens. No unfinished command is replayed automatically. Evidence remains linked to run %s.", s.snapshot.Tools, s.snapshot.CompletedTools, s.snapshot.FailedTools, s.snapshot.PendingTools, s.snapshot.Calls, s.snapshot.Tokens, s.snapshot.ID)
	if len(s.snapshot.RecentTools) > 0 {
		s.snapshot.Checkpoint += " Returned tool steps: " + strings.Join(s.snapshot.RecentTools, ", ") + "."
	}
	if len(s.snapshot.PendingIDs) > 0 {
		s.snapshot.Checkpoint += " Pending tool references: " + strings.Join(s.snapshot.PendingIDs, ", ") + "."
	}
	if e := s.persist(); e != nil {
		s.snapshot.Status = "blocked"
		s.snapshot.Code = "state_unavailable"
		s.snapshot.Message = "Execution status could not be persisted."
	}
	out := s.snapshot
	out.RecentTools = append([]string(nil), out.RecentTools...)
	out.PendingIDs = append([]string(nil), out.PendingIDs...)
	return out
}

type durationKey struct{}

func WithDuration(ctx context.Context, seconds int) context.Context {
	return context.WithValue(ctx, durationKey{}, seconds)
}
func DurationFrom(ctx context.Context) int { n, _ := ctx.Value(durationKey{}).(int); return n }

func (s *State) Executor(id int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.ExecutorID = id
	_ = s.persist()
}

func (s *State) ExecutionError() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalError
}
