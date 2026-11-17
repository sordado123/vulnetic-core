package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/config"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
)

// maxChatUpload caps a single chat-attachment upload request (memory + spill).
const maxChatUpload = 21 << 20 // includes multipart overhead; each file is capped at 20 MiB

// safeChatID guards the {id} path segment against traversal — task ids are numeric,
// session ids are alnum/_/- ; anything with "/" or ".." is rejected.
var safeChatID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// chatAttachment is one uploaded file as the frontend + agent see it. Path is relative
// to the chat's working dir (e.g. "uploads/report.txt"), which is the agent's CWD, so
// it can Read/Bash the file directly; Name/Size drive the UI card.
type chatAttachment struct {
	Token string `json:"token,omitempty"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	// Abs is the absolute on-disk path (m.dir is already absolute). For pre-task staging
	// (scope=staging) the frontend uses it to write the prompt into the description; task/session use composeAgentMessage, which builds the path in the backend.
	Abs string `json:"abs,omitempty"`
}

// chatUpload implements method-1 file support: it saves one or more files into a chat's
// working dir under uploads/, so the agent opens them with its existing Read/Bash tools
// and the sent message carries their paths. No LLM-layer change, no multimodal.
//
// POST /api/chat/upload?scope=task|session|staging&id=<id>, multipart field "file"
// (repeatable). Returns {attachments:[{name,path,size,abs}]}. Target dir mirrors the
// agent CWD layout:
//
//	scope=task    → <workDir>/tasks/<id>/uploads/
//	scope=session → <workDir>/sessions/<id>/uploads/
//	scope=staging → <workDir>/drafts/<id>/uploads/   (pre-task staging: the task has no ID yet;
//	                files land here first and the frontend writes their abs paths into the task description)
func (s *Server) chatUpload(w http.ResponseWriter, r *http.Request) {
	if config.SaaSMode() {
		s.remoteChatUpload(w, r)
		return
	}
	var sub string
	taskScoped := false
	switch r.URL.Query().Get("scope") {
	case "task":
		sub = "tasks"
		taskScoped = true
	case "session":
		sub = "sessions"
	case "staging":
		sub = "drafts"
	default:
		writeErr(w, 400, "scope must be task / session / staging")
		return
	}
	id := r.URL.Query().Get("id")
	if !safeChatID.MatchString(id) {
		writeErr(w, 400, "invalid id")
		return
	}
	if taskScoped {
		// Was s.m.ResolveTask: unscoped, so account B's token could write
		// files straight into account A's task upload directory.
		if _, ok := s.taskForAccount(r, id); !ok {
			writeErr(w, 404, "task not found")
			return
		}
		if !s.engine.beginTaskOperation(id) {
			writeErr(w, http.StatusConflict, "Task is being deleted; cannot upload attachments")
			return
		}
		defer s.engine.decInflight(id)
	}
	dir := filepath.Join(s.m.dir, sub, id, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "failed to create directory: "+err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "failed to parse the upload or size limit exceeded: "+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		dest := uniqueUploadPath(dir, name)
		if err := saveUpload(hdr, dest); err != nil {
			writeErr(w, 500, "Save failed: "+err.Error())
			return
		}
		base := filepath.Base(dest)
		out = append(out, chatAttachment{Name: base, Path: "uploads/" + base, Size: hdr.Size, Abs: dest})
	}
	writeJSON(w, 200, map[string]any{"attachments": out})
}

func (s *Server) remoteChatUpload(w http.ResponseWriter, r *http.Request) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return
	}
	id, scope := r.URL.Query().Get("id"), r.URL.Query().Get("scope")
	if !safeChatID.MatchString(id) {
		writeErr(w, 400, "invalid id")
		return
	}
	if scope == "task" {
		s.remoteTaskChatUpload(w, r)
		return
	}
	var targetID int64
	switch scope {
	case "task":
		task, ok := s.taskForAccount(r, id)
		if !ok {
			writeErr(w, 404, "task not found")
			return
		}
		if !s.engine.beginTaskOperation(id) {
			writeErr(w, 409, "Task is being deleted; cannot upload attachments")
			return
		}
		defer s.engine.decInflight(id)
		if bound := task.lifecycleSnapshot().SSHTargetID; bound != nil {
			targetID = *bound
		}
	case "session":
		convID, err := strconv.ParseInt(strings.TrimPrefix(id, "conv-"), 10, 64)
		if err != nil || !strings.HasPrefix(id, "conv-") {
			writeErr(w, 404, "conversation not found")
			return
		}
		conv, err := s.m.pg.ForAccount(accountID).GetConversation(convID)
		if err != nil || conv == nil {
			writeErr(w, 404, "conversation not found")
			return
		}
		if conv.SSHTargetID != nil {
			targetID = *conv.SSHTargetID
		}
	case "staging":
		targetID, _ = strconv.ParseInt(r.URL.Query().Get("ssh_target_id"), 10, 64)
	default:
		writeErr(w, 400, "scope must be task / session / staging")
		return
	}
	sub := map[string]string{"task": "tasks", "session": "sessions", "staging": "drafts"}[scope]
	ex, closeExecutor, err := s.remoteExecutor(accountID, targetID, fmt.Sprintf(".vulnetic/accounts/%d/%s/%s", accountID, sub, id))
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	defer closeExecutor()
	root, ok := s.workspaceRoot(w, r)
	if !ok {
		return
	}
	defer root.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	if err = r.ParseMultipartForm(1 << 20); err != nil {
		writeErr(w, 413, "Upload exceeds the 20 MiB file limit")
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing file")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	directory := filepath.Join(sub, id, "uploads")
	if err = root.MkdirAll(directory, 0700); err != nil {
		writeErr(w, 503, "Artifact storage unavailable")
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, header := range files {
		name := filepath.Base(header.Filename)
		if name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
			writeErr(w, 400, "invalid file name")
			return
		}
		source, err := header.Open()
		if err != nil {
			writeErr(w, 400, "Unreadable upload")
			return
		}
		data, err := io.ReadAll(io.LimitReader(source, 20<<20+1))
		source.Close()
		if err != nil {
			writeErr(w, 400, "Unreadable upload")
			return
		}
		name = uuid.NewString() + "-" + name
		path := filepath.Join(directory, name)
		if scope == "staging" {
			f := taskFile{ID: name[:36], Name: header.Filename, RemoteName: name}
			err = s.saveTaskFile(&Task{AccountID: accountID, ID: "draft-" + id}, f, data)
		} else {
			if err = workspaceQuota(root, path, int64(len(data))); err != nil {
				writeErr(w, 413, err.Error())
				return
			}
			if err = saveRootBytes(root, path, data); err != nil {
				if errors.Is(err, artifactquota.ErrExceeded) {
					writeErr(w, 413, err.Error())
					return
				}
				writeErr(w, 503, "Unable to persist artifact")
				return
			}
		}
		if err != nil {
			taskFileError(w, err)
			return
		}

		remotePath, err := ex.Upload(ctx, name, bytes.NewReader(data))
		if err != nil {
			_ = root.Remove(path)
			writeErr(w, 502, "Remote upload failed; the saved draft remains in Vulnetic. Check the VPS before retrying")
			return
		}
		attachment := chatAttachment{Name: header.Filename, Path: remotePath, Abs: remotePath, Size: int64(len(data))}
		attachment.Token = s.attachmentToken(accountID, targetID, attachment)
		out = append(out, attachment)
	}
	writeJSON(w, 200, map[string]any{"attachments": out})
}

func (s *Server) attachmentToken(accountID, targetID int64, attachment chatAttachment) string {
	payload, _ := json.Marshal([]any{accountID, targetID, attachment.Name, attachment.Path, attachment.Abs, attachment.Size})
	mac := hmac.New(sha256.New, s.jwtKey)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) validUploadedAttachments(accountID int64, targetID *int64, attachments []chatAttachment) bool {
	if !config.SaaSMode() || len(attachments) == 0 {
		return true
	}
	if accountID <= 0 || targetID == nil || *targetID <= 0 || len(s.jwtKey) < 32 {
		return false
	}
	for _, attachment := range attachments {
		if attachment.Token == "" || !hmac.Equal([]byte(attachment.Token), []byte(s.attachmentToken(accountID, *targetID, attachment))) {
			return false
		}
	}
	return true
}

// uniqueUploadPath returns dir/name, or dir/name-1, dir/name-2… when it already exists,
// so re-uploading the same filename never clobbers a prior attachment.
func uniqueUploadPath(dir, name string) string {
	dest := filepath.Join(dir, name)
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		return dest
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// composeAgentMessage appends an attachment manifest to the user's message so the agent
// knows which files were uploaded and where to Read them. baseDir is the agent's working
// dir (its CWD); we emit ABSOLUTE paths (baseDir + relative) so the agent can Read/Bash
// them unambiguously regardless of how it interprets relative paths.
func composeAgentMessage(msg string, atts []chatAttachment, baseDir string) string {
	if len(atts) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\n\n[User-uploaded attachments] (absolute paths; use Read/Bash to view them):")
	for _, a := range atts {
		path := filepath.Join(baseDir, a.Path)
		if config.SaaSMode() {
			path = a.Path
		}
		fmt.Fprintf(&b, "\n- %s (%s)", path, humanBytes(a.Size))
	}
	return b.String()
}

// userActivityWithAttachments builds the persisted 'user' activity. With attachments,
// Detail holds JSON {text, attachments} so the transcript renders text + attachment
// cards; Summary stays the plain text (the list payload omits Detail, lazy-loaded).
func userActivityWithAttachments(worker, text string, atts []chatAttachment) db.Activity {
	a := db.Activity{Worker: worker, Kind: "user", Summary: text}
	if len(atts) > 0 {
		blob, _ := json.Marshal(map[string]any{"text": text, "attachments": atts})
		a.Detail = string(blob)
	}
	return a
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
