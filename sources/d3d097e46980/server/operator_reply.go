package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/operatorinput"
)

func (s *Server) prepareOperatorReply(accountID int64, item db.OperatorRequest, answer string, approved *bool) (string, string, error) {
	if err := item.Input.Validate(); err != nil {
		return "", "", err
	}
	prefix := fmt.Sprintf("Reply to operator request #%d", item.Seq)
	switch item.Input.Type {
	case "confirm_send_code":
		if approved == nil {
			return "", "", fmt.Errorf("choose whether one code may be sent")
		}
		if !*approved {
			return prefix + ": The user declined sending or resending the code. Do not send it. Ask about another authorized authentication method.", "", nil
		}
		return prefix + ": The user explicitly permits sending ONE verification code for " + item.Input.TargetURL + ". This does not authorize repeated sends or expand scope. After sending, call ask_operator with input_type=one_time_code and wait.", "", nil
	case "action":
		if approved == nil {
			return "", "", fmt.Errorf("confirm whether you completed the requested action")
		}
		return fmt.Sprintf("%s: The user reports the requested action completed=%t. Verify the resulting state; this is not proof of successful authentication or broader authorization.", prefix, *approved), "", nil
	case "one_time_code", "session":
		value, masks, err := operatorinput.Prepare(item.Input, answer)
		if err != nil {
			return "", "", err
		}
		scope := operatorinput.Scope{AccountID: accountID, TaskID: item.TaskID, ConversationID: item.ConversationID}
		pg := s.m.pg.ForAccount(accountID)
		if item.ConversationID > 0 {
			c, err := pg.GetConversation(item.ConversationID)
			if err != nil || c == nil || c.SSHTargetID == nil {
				return "", "", fmt.Errorf("conversation executor unavailable")
			}
			scope.ExecutorID = *c.SSHTargetID
			if c.SourceTaskID != nil {
				scope.TaskID = *c.SourceTaskID
			}
		} else {
			t, err := pg.GetTask(item.TaskID)
			if err != nil || t == nil || t.SSHTargetID == nil {
				return "", "", fmt.Errorf("task executor unavailable")
			}
			scope.ExecutorID = *t.SSHTargetID
		}
		if _, err = s.verifiedTarget(accountID, scope.ExecutorID); err != nil {
			return "", "", err
		}
		ref, expires, err := s.operatorInputs.Put(scope, value, masks)
		if err != nil {
			return "", "", err
		}
		format := "one-time code"
		if item.Input.Type == "session" {
			format = "JSON object containing origin and cookies, with original expiry and HttpOnly attributes preserved"
		}
		message := fmt.Sprintf("%s: The user supplied sensitive input (%s) for %s. Read executor environment variable %s in the invoked program. Delivery reference expires at %s; it is lost on platform restart and never renews executor access. Name the variable literally in the Bash launch command so it can be injected, including when running a script from a file. Do not echo, paste into command source or record its value. Use only for this authentication flow and verify success before continuing. An expired or rejected code requires a fresh user request; do not guess or resend automatically.", prefix, format, item.Input.TargetURL, ref, expires.UTC().Format(time.RFC3339))
		return message, ref, nil
	default:
		answer = strings.TrimSpace(answer)
		if answer == "" || len([]rune(answer)) > 4000 {
			return "", "", fmt.Errorf("answer must contain 1 to 4000 characters")
		}
		return answer, "", nil
	}
}

func (s *Server) replyOperatorRequest(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	var req struct {
		TaskID         int64  `json:"task_id"`
		IntentID       int64  `json:"intent_id"`
		ConversationID int64  `json:"conversation_id"`
		Seq            int64  `json:"seq"`
		Answer         string `json:"answer"`
		Approved       *bool  `json:"approved"`
		RequestID      string `json:"request_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF || req.Seq <= 0 {
		writeErr(w, 400, "Invalid operator reply")
		return
	}
	items, err := s.m.pg.ForAccount(accountID).OperatorRequests()
	if err != nil {
		writeErr(w, 503, "Operator requests unavailable")
		return
	}
	var found *db.OperatorRequest
	for i := range items {
		item := &items[i]
		if item.Seq == req.Seq && item.TaskID == req.TaskID && item.IntentID == req.IntentID && item.ConversationID == req.ConversationID {
			found = item
			break
		}
	}
	if found == nil {
		writeErr(w, 404, "Request was answered, cancelled or is unavailable to this account")
		return
	}
	message, ref, err := s.prepareOperatorReply(accountID, *found, req.Answer, req.Approved)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.RequestID == "" {
		req.RequestID = uuid.NewString()
	}
	if !validWorkerMessageRequestID(req.RequestID) {
		if ref != "" {
			s.operatorInputs.Remove(ref)
		}
		writeErr(w, 400, "Invalid reply request ID")
		return
	}
	data, _ := json.Marshal(map[string]any{"message": message, "request_id": req.RequestID})
	forward := r.Clone(r.Context())
	forward.Body = io.NopCloser(bytes.NewReader(data))
	forward.ContentLength = int64(len(data))
	response := &bufferedTenantResponse{header: make(http.Header), status: 200}
	if found.ConversationID > 0 {
		forward.SetPathValue("id", strconv.FormatInt(found.ConversationID, 10))
		s.pgSendConversationMessage(response, forward)
	} else {
		forward.SetPathValue("id", strconv.FormatInt(found.TaskID, 10))
		forward.SetPathValue("iid", strconv.FormatInt(found.IntentID, 10))
		s.sendWorkerMessage(response, forward)
	}
	if response.status >= 400 && ref != "" {
		s.operatorInputs.Remove(ref)
	}
	response.send(w)
}

var numericOperatorCode = regexp.MustCompile(`^[0-9]{4,12}$`)

// Existing chat/Worker composers also protect a numeric reply to a pending code request.
func (s *Server) protectOperatorCode(accountID, taskID, intentID, conversationID int64, message string) (string, error) {
	if !numericOperatorCode.MatchString(strings.TrimSpace(message)) {
		return message, nil
	}
	items, err := s.m.pg.ForAccount(accountID).OperatorRequests()
	if err != nil {
		return "", err
	}
	for _, item := range items {
		if item.Input.Type == "one_time_code" && item.TaskID == taskID && item.IntentID == intentID && item.ConversationID == conversationID {
			prepared, _, err := s.prepareOperatorReply(accountID, item, message, nil)
			return prepared, err
		}
	}
	return message, nil
}

func (s *Server) withOperatorInputEnvironment(scope operatorinput.Scope, base func(string) ([]string, error)) func(string) ([]string, error) {
	return func(command string) ([]string, error) {
		env, err := s.operatorInputs.Environment(scope, command)
		if err != nil {
			return nil, err
		}
		if base != nil {
			other, err := base(command)
			if err != nil {
				return nil, err
			}
			env = append(env, other...)
		}
		return env, nil
	}
}
