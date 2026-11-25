package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/operatorinput"
	"github.com/sordado123/vulnetic/internal/runstate"
)

const askOperatorMaxImage = 10 << 20

var askOperatorImageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".gif": true}

// toolAskOperator lets a worker formally request operator input (captcha, OTP,
// 2FA, a decision): the question and an optional screenshot land in the intent's
// transcript as a user-role turn with an attachment card, and the intent pauses.
// The operator replies through the existing message-to-worker flow; the reply
// resumes the run with the answer as the next input (#41).
func (s *Server) toolAskOperator() actool.CoreTool {
	return wrTool("ask_operator",
		"Request user input needed to continue a chat or Worker and notify the account. Select input_type: text for an answer, action for a manual step, confirm_send_code for permission to send ONE code, one_time_code for a delivered/authenticator code, session for optional cookies. Authentication requests require target_url and a masked destination_hint. Codes/sessions are submitted through Respond and delivered as temporary executor environment references; never ask to paste them into ordinary messages or save them as credentials. Wait for the reply in this exact execution; independent Workers continue. Asking does not grant approval. For environmental blocks include the precise single copy-pastable command the user should run and what non-secret result to return, then wait; do not retry or work around the blocked prerequisite.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"question": map[string]any{
					"type":        "string",
					"description": "What you need from the operator, precisely (e.g. 'enter the 6-digit code sent to x@y', 'solve the captcha in the attached screenshot'). For environmental blocks: the exact single command they should run in their own terminal (one line, copy-pastable) and what to paste back.",
				},
				"image_path": map[string]any{
					"type":        "string",
					"description": "Optional path to a screenshot (png/jpg/jpeg/webp/gif, max 10MB), e.g. the browser_take_screenshot output. It is copied into the task uploads and shown to the operator.",
				},
				"input_type":       map[string]any{"type": "string", "enum": []string{"text", "action", "confirm_send_code", "one_time_code", "session"}, "description": "Use confirm_send_code BEFORE sending/resending a login code, then one_time_code after consent and delivery. Use session for user-supplied cookies, action for a manual step, text for other answers."},
				"target_url":       map[string]any{"type": "string", "maxLength": 2048, "description": "Exact authorized service URL; required for authentication and session requests. No credentials or secret URL parameters."},
				"delivery":         map[string]any{"type": "string", "enum": []string{"email", "sms", "totp", "push", "browser", "other"}},
				"destination_hint": map[string]any{"type": "string", "maxLength": 160, "description": "Masked destination, e.g. j***@example.org or phone ending 1234; never a code or cookie value."},
			},
			"required": []any{"question"},
		},
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var req struct {
				Question        string `json:"question"`
				ImagePath       string `json:"image_path"`
				InputType       string `json:"input_type"`
				TargetURL       string `json:"target_url"`
				Delivery        string `json:"delivery"`
				DestinationHint string `json:"destination_hint"`
			}
			_ = json.Unmarshal(in, &req)
			q := strings.TrimSpace(req.Question)
			if q == "" {
				return actool.Errorf("Error: question is required"), nil
			}
			if len(q) > 5000 {
				return actool.Errorf("question exceeds size limit"), nil
			}
			spec := operatorinput.Spec{Type: req.InputType, TargetURL: req.TargetURL, Delivery: req.Delivery, DestinationHint: req.DestinationHint}
			if err := spec.Validate(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			detail, _ := json.Marshal(map[string]any{"text": q, "input_request": spec})
			ri := agent.RunInfoFrom(ctx)
			if convID := intercept.ConvIDFromContext(ctx); convID > 0 && ri.IntentID == 0 {
				if ri.AccountID <= 0 {
					return actool.Errorf("authenticated conversation required"), nil
				}
				state := runstate.From(ctx)
				if state == nil {
					return actool.Errorf("execution state unavailable"), nil
				}
				if req.ImagePath != "" {
					return actool.Errorf("attach an uploaded artifact instead of a local image path"), nil
				}
				if _, err := s.m.pg.ForAccount(ri.AccountID).AppendConvActivity(convID, db.Activity{Kind: "operator_request", Worker: "assistant", Summary: q, Detail: string(detail)}); err != nil {
					return actool.Errorf("unable to persist operator question"), nil
				}
				state.Terminal(fmt.Errorf("waiting_operator: question delivered"))
				return actool.Text("Question delivered and shown in notifications. Wait for the user's reply in this chat."), nil
			}
			if ri.TaskID == 0 || ri.IntentID == 0 {
				return actool.Errorf("Error: ask_operator can only be used inside a worker intent run"), nil
			}
			taskID := fmt.Sprintf("%d", ri.TaskID)
			t := s.m.ResolveTask(taskID)
			if t == nil || ri.AccountID <= 0 || t.AccountID != ri.AccountID {
				return actool.Errorf("Error: task not found"), nil
			}
			state := runstate.From(ctx)
			if state == nil {
				return actool.Errorf("Error: execution state unavailable; cannot wait for operator"), nil
			}
			att, err := stageAskOperatorImage(s.m.dir, taskID, req.ImagePath)
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			text := "OPERATOR INPUT REQUESTED: " + q + " (this intent is pausing; reply here to resume it with your answer)"
			act := userActivityWithAttachments("worker", text, att)
			detail, _ = json.Marshal(map[string]any{"text": text, "attachments": att, "input_request": spec})
			act.Detail = string(detail)
			node := ri.IntentID
			act.NodeID = &node
			if saved := s.engine.emitActivity(t, act); saved.ID <= 0 {
				return actool.Errorf("unable to persist operator question"), nil
			}
			if spec.Type == "confirm_send_code" || spec.Type == "one_time_code" || spec.Type == "session" || strings.Contains(strings.ToLower(q), "captcha") || strings.Contains(strings.ToLower(q), "login") || strings.Contains(strings.ToLower(q), "2fa") {
				if err := s.saveTaskPrerequisite(ctx, "authentication", "blocked", q); err != nil {
					return actool.Errorf("unable to persist authentication prerequisite"), nil
				}
			}
			if err := s.saveTaskPrerequisite(ctx, "operator", "blocked", q); err != nil {
				return actool.Errorf("unable to persist operator prerequisite"), nil
			}
			// Yield at the tool boundary; cancelling and waiting on this same Worker deadlocks.
			state.Terminal(fmt.Errorf("waiting_operator: question delivered"))
			return actool.Text("Question delivered. Waiting for operator input; the operator's reply will resume this intent. No action was approved by an empty reply."), nil
		})
}

// stageAskOperatorImage copies the referenced image into the task's uploads dir
// (the same place chat uploads land, so the transcript attachment card resolves)
// and returns the attachment descriptor. Empty src returns no attachment.
func stageAskOperatorImage(dataDir, taskID, src string) ([]chatAttachment, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, nil
	}
	if config.SaaSMode() {
		return nil, fmt.Errorf("local image paths are unavailable; attach an uploaded artifact from this task")
	}
	ext := strings.ToLower(filepath.Ext(src))
	if !askOperatorImageExt[ext] {
		return nil, fmt.Errorf("image_path must be a png/jpg/jpeg/webp/gif file, got %q", filepath.Base(src))
	}
	st, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("image not readable: %v", err)
	}
	if st.Size() > askOperatorMaxImage {
		return nil, fmt.Errorf("image too large (%s, max 10MB)", humanBytes(st.Size()))
	}
	dir := filepath.Join(dataDir, "tasks", taskID, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("ask-operator-%d%s", time.Now().Unix(), ext)
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return nil, err
	}
	return []chatAttachment{{Name: name, Path: "uploads/" + name, Size: st.Size()}}, nil
}
