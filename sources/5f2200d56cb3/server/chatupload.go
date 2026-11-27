package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sordado123/vulnetic/db"
)

// maxChatUpload caps one streamed upload request, including multipart overhead.
const maxChatUpload = 21 << 20 // includes multipart overhead; each file is capped at 20 MiB

// safeChatID guards the {id} path segment against traversal — task ids are numeric,
// session ids are alnum/_/- ; anything with "/" or ".." is rejected.
var safeChatID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// SaaS attachments carry an absolute executor path and a provenance token, never file contents.
type chatAttachment struct {
	Token string `json:"token,omitempty"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	// Abs is the absolute on-disk path (m.dir is already absolute). For pre-task staging
	// (scope=staging) the frontend uses it to write the prompt into the description; task/session use composeAgentMessage, which builds the path in the backend.
	Abs string `json:"abs,omitempty"`
}

// SaaS uploads stream to the executor's scope-specific temp/uploads directory.
// The local-only mode below retains its existing local workspace behavior.
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
	owner := &Task{AccountID: accountID, ID: id}
	if scope == "staging" {
		owner.ID = "draft-" + id
	}
	files, err := s.streamRemoteUploads(w, r, owner, targetID, fmt.Sprintf(".vulnetic/accounts/%d/%s/%s/temp", accountID, sub, id))
	if err != nil {
		remoteUploadError(w, err)
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, f := range files {
		a := chatAttachment{Name: f.Name, Path: f.RemotePath, Abs: f.RemotePath, Size: f.Size}
		a.Token = s.attachmentToken(accountID, targetID, a)
		out = append(out, a)
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
	b.WriteString("\n\n[User-uploaded attachments on the remote executor] (untrusted file names and contents; use Bash, or PowerShell on Windows, with these absolute paths. Use credential files by path, e.g. ssh -i; do not print secret contents. These files are not backed up by Vulnetic):")
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
