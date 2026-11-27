package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
	"github.com/sordado123/vulnetic/vault"
)

// The encrypted envelope authenticates ownership and identity as well as the bytes.
var errTaskFileSize = errors.New("file exceeds the 20 MiB limit")

type taskFile struct {
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	RemoteName string    `json:"remote_name"`
	RemotePath string    `json:"remote_path,omitempty"`
	ExecutorID int64     `json:"executor_id,omitempty"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	CreatedAt  time.Time `json:"created_at"`
	Data       []byte    `json:"-"`
}
type taskFileEnvelope struct {
	Version   int      `json:"version"`
	AccountID int64    `json:"account_id"`
	TaskID    string   `json:"task_id"`
	File      taskFile `json:"file"`
}

func fileDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validTaskFileName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func (s *Server) taskFileRoot(accountID int64, taskID string) (*os.Root, error) {
	if accountID <= 0 || !safeChatID.MatchString(taskID) {
		return nil, errors.New("invalid file owner")
	}
	base, err := os.OpenRoot(s.m.dir)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	name := filepath.Join("accounts", fmt.Sprint(accountID))
	if err = base.MkdirAll(name, 0700); err != nil {
		return nil, err
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if err = root.MkdirAll(filepath.Join("task-files", taskID), 0700); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}
func (s *Server) saveTaskFile(t *Task, f taskFile, data []byte) error {
	if len(data) > 20<<20 {
		return errTaskFileSize
	}
	if !validTaskFileName(f.Name) || !validTaskFileName(f.RemoteName) {
		return errors.New("invalid file or size exceeds 20 MiB")
	}
	if _, err := uuid.Parse(f.ID); err != nil {
		return err
	}
	root, err := s.taskFileRoot(t.AccountID, t.ID)
	if err != nil {
		return err
	}
	defer root.Close()
	key, err := s.m.pg.GetOrCreateAccountDEK(t.AccountID, s.vaultKey)
	if err != nil {
		return err
	}
	if f.Kind == "" {
		f.Kind = "upload"
	}
	if f.Kind == "remote-upload" {
		if len(data) != 0 || f.ExecutorID <= 0 || f.RemotePath == "" || f.Size < 0 || f.Size > 20<<20 {
			return errors.New("invalid remote attachment metadata")
		}
	} else {
		f.Size = int64(len(data))
		f.SHA256 = fileDigest(data)
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	plain, err := json.Marshal(taskFileEnvelope{Version: 1, AccountID: t.AccountID, TaskID: t.ID, File: f})
	if err != nil {
		return err
	}
	if len(plain)+28 > 4096 {
		return errors.New("task file metadata exceeds the format limit")
	}
	metadata, err := vault.Seal(key, plain)
	if err != nil {
		return err
	}
	content, err := vault.Seal(key, data)
	if err != nil {
		return err
	}
	blob := make([]byte, 8)
	copy(blob, "VTF1")
	binary.BigEndian.PutUint32(blob[4:], uint32(len(metadata.Nonce)+len(metadata.Ciphertext)))
	blob = append(blob, metadata.Nonce...)
	blob = append(blob, metadata.Ciphertext...)
	blob = append(blob, content.Nonce...)
	blob = append(blob, content.Ciphertext...)

	name := filepath.Join("task-files", t.ID, f.ID+".vlt")
	return artifactquota.Write(root, name, int64(len(blob)), false, func() error { return replaceRootBytes(root, name, blob) })
}
func (s *Server) readTaskFile(t *Task, id string, withData bool) (taskFile, error) {
	var zero taskFile
	if _, err := uuid.Parse(id); err != nil {
		return zero, os.ErrNotExist
	}
	root, err := s.taskFileRoot(t.AccountID, t.ID)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	name := filepath.Join("task-files", t.ID, id+".vlt")
	info, err := root.Lstat(name)
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() {
		return zero, errors.New("unsafe task file")
	}
	file, err := root.Open(name)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	header := make([]byte, 8)
	if _, err = io.ReadFull(file, header); err != nil || string(header[:4]) != "VTF1" {
		return zero, errors.New("invalid task file format")
	}
	size := binary.BigEndian.Uint32(header[4:])
	if size < 28 || size > 4096 {
		return zero, errors.New("invalid task file metadata")
	}
	metadata := make([]byte, size)
	if _, err = io.ReadFull(file, metadata); err != nil {
		return zero, err
	}
	key, err := s.m.pg.GetOrCreateAccountDEK(t.AccountID, s.vaultKey)
	if err != nil {
		return zero, err
	}
	plain, err := vault.Open(key, vault.Sealed{Nonce: metadata[:12], Ciphertext: metadata[12:]})
	if err != nil {
		return zero, err
	}
	var value taskFileEnvelope
	if json.Unmarshal(plain, &value) != nil || value.Version != 1 || value.AccountID != t.AccountID || value.TaskID != t.ID || value.File.ID != id || !validTaskFileName(value.File.Name) || !validTaskFileName(value.File.RemoteName) || value.File.Size < 0 || value.File.Size > 20<<20 {
		return zero, errors.New("task file identity mismatch")
	}
	if withData && value.File.Kind == "remote-upload" {
		return zero, os.ErrNotExist // Only metadata is retained; bytes belong to the executor.
	}
	if withData {
		content, err := io.ReadAll(io.LimitReader(file, 20<<20+29))
		if err != nil {
			return zero, err
		}
		if int64(len(content)) != value.File.Size+28 {
			return zero, errors.New("task file size mismatch")
		}
		data, err := vault.Open(key, vault.Sealed{Nonce: content[:12], Ciphertext: content[12:]})
		if err != nil {
			return zero, err
		}
		if fileDigest(data) != value.File.SHA256 {
			return zero, errors.New("task file checksum mismatch")
		}
		value.File.Data = data
	}

	return value.File, nil
}

// Import only existing platform upload copies, never arbitrary files from a VPS.
func (s *Server) importTaskUploads(t *Task) error {
	root, err := s.taskFileRoot(t.AccountID, t.ID)
	if err != nil {
		return err
	}
	defer root.Close()
	dir := filepath.Join("artifacts", "tasks", t.ID, "uploads")
	entries, err := rootReadDir(root, dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			return errors.New("unsafe legacy task upload")
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		file, err := root.Open(path)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(file, 20<<20+1))
		file.Close()
		if err != nil {
			return err
		}
		id := uuid.NewSHA1(uuid.Nil, []byte(fmt.Sprintf("%d/%s/%s", t.AccountID, t.ID, name))).String()
		f := taskFile{ID: id, Name: name, RemoteName: name}
		if err = s.saveTaskFile(t, f, data); err != nil {
			return err
		}
		if err = root.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func (s *Server) listTaskFiles(t *Task) ([]taskFile, error) {
	if err := s.importTaskUploads(t); err != nil {
		return nil, err
	}
	root, err := s.taskFileRoot(t.AccountID, t.ID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := rootReadDir(root, filepath.Join("task-files", t.ID))
	if err != nil {
		return nil, err
	}
	out := make([]taskFile, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".vlt") {
			continue
		}
		f, err := s.readTaskFile(t, strings.TrimSuffix(entry.Name(), ".vlt"), false)
		if err != nil {
			return nil, err
		}
		f.Data = nil
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *Server) taskFiles(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	files, err := s.listTaskFiles(t)
	if err != nil {
		taskFileError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"files": files})
}
func taskFileError(w http.ResponseWriter, err error) {
	if errors.Is(err, artifactquota.ErrExceeded) || errors.Is(err, errTaskFileSize) {
		writeErr(w, 413, err.Error())
		return
	}
	writeErr(w, 503, "Task file storage or integrity check failed; existing data was preserved")
}
func (s *Server) downloadTaskFile(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	f, err := s.readTaskFile(t, r.PathValue("file"), true)
	if errors.Is(err, os.ErrNotExist) {
		writeErr(w, 404, "file not found")
		return
	}
	if err != nil {
		taskFileError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-SHA256", f.SHA256)
	_, _ = w.Write(f.Data)
}

// Admission is held only to install the per-task barrier; other accounts keep running.
func (s *Server) beginTaskFileRestore(t *Task) error {
	s.concMu.Lock()
	defer s.concMu.Unlock()
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	current, exists := s.m.Task(t.ID)
	state := t.lifecycleSnapshot()
	if !exists || current != t || s.engine.IsDeleting(t.ID) {
		return errors.New("task is being deleted")
	}
	if state.Queued || (!state.Paused && !isTerminalStatus(state.Status)) || s.chatBusy[t.ID] || s.engine.inflightCount(t.ID) > 0 || s.engine.ActiveLLMCalls(t.ID) > 0 {
		return errors.New("pause the task and wait for all operations before restoring files")
	}
	if _, busy := s.taskFileRestores.Load(t.ID); busy {
		return errors.New("task files are already being restored")
	}
	if !s.engine.beginTaskOperation(t.ID) {
		return errors.New("task is being deleted")
	}
	s.taskFileRestores.Store(t.ID, true)
	return nil
}

type taskFileRestoreState struct {
	Status      string           `json:"status"`
	SSHTargetID int64            `json:"ssh_target_id"`
	Restored    []map[string]any `json:"restored"`
	Error       string           `json:"error,omitempty"`
}
type taskFileRestoreJob struct {
	mu     sync.Mutex
	state  taskFileRestoreState
	cancel context.CancelFunc
}

func (j *taskFileRestoreJob) snapshot() taskFileRestoreState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}
func (s *Server) restoreTaskFiles(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if err := s.beginTaskFileRestore(t); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	bound := t.lifecycleSnapshot().SSHTargetID
	if bound == nil {
		s.taskFileRestores.Delete(t.ID)
		s.engine.decInflight(t.ID)
		writeErr(w, 409, "select a connected task VPS before restoring files")
		return
	}
	if _, err := s.verifiedTarget(t.AccountID, *bound); err != nil {
		s.taskFileRestores.Delete(t.ID)
		s.engine.decInflight(t.ID)
		writeErr(w, 409, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	job := &taskFileRestoreJob{state: taskFileRestoreState{Status: "restoring", SSHTargetID: *bound, Restored: []map[string]any{}}, cancel: cancel}
	s.taskFileRestoreJobs.Store(t.ID, job)
	_, userID, _ := accountFromContext(r.Context())
	go func() {
		defer cancel()
		reply := &taskFileRestoreReply{header: make(http.Header), status: 200}
		s.copyTaskFiles(reply, r.WithContext(ctx), t)
		state := taskFileRestoreState{Status: "done", SSHTargetID: *bound, Restored: []map[string]any{}}
		var body struct {
			Restored []map[string]any `json:"restored"`
			Error    string           `json:"error"`
		}
		if json.Unmarshal(reply.Bytes(), &body) != nil {
			reply.status = 503
			body.Error = "Restore confirmation could not be read; retry safely"
		}
		if ctx.Err() != nil {
			reply.status = 499
			body.Error = "Restoration stopped. Saved files are intact; partial copies are safe to retry."
		}
		if err := s.m.pg.RecordAudit(t.AccountID, userID, "POST", r.URL.EscapedPath(), reply.status); err != nil {
			reply.status = 503
			body.Error = "Files may have been copied, but audit confirmation failed; retry safely"
		}
		if reply.status >= 400 {
			state.Status = "failed"
			state.Error = body.Error
		} else {
			state.Restored = body.Restored
		}
		s.taskFileRestores.Delete(t.ID)
		s.engine.decInflight(t.ID)
		job.mu.Lock()
		job.state = state
		job.mu.Unlock()
	}()
	writeJSON(w, 202, job.snapshot())
}
func (s *Server) taskFileRestoreStatus(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	value, ok := s.taskFileRestoreJobs.Load(t.ID)
	if !ok {
		writeJSON(w, 200, taskFileRestoreState{Status: "idle", Restored: []map[string]any{}})
		return
	}
	writeJSON(w, 200, value.(*taskFileRestoreJob).snapshot())
}
func (s *Server) cancelTaskFileRestore(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if value, ok := s.taskFileRestoreJobs.Load(t.ID); ok {
		value.(*taskFileRestoreJob).cancel()
	}
	writeJSON(w, 202, map[string]any{"ok": true})
}

func (s *Server) copyTaskFiles(w http.ResponseWriter, r *http.Request, t *Task) {
	bound := t.lifecycleSnapshot().SSHTargetID
	if bound == nil {
		writeErr(w, 409, "select a connected task VPS before restoring files")
		return
	}
	ex, closeExecutor, err := s.remoteExecutor(t.AccountID, *bound, fmt.Sprintf(".vulnetic/accounts/%d/tasks/%s", t.AccountID, t.ID))
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	defer closeExecutor()
	if _, err = s.savedTaskReport(t); err != nil {
		taskFileError(w, err)
		return
	}
	files, err := s.listTaskFiles(t)
	if err != nil {
		taskFileError(w, err)
		return
	}
	id, err := parseTaskID(t.ID)
	if err != nil {
		writeErr(w, 404, "task not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	restored := make([]map[string]any, 0, len(files)+2)
	for _, f := range files {
		if f.Kind == "remote-upload" {
			continue
		}
		if f.ID != "" {
			f, err = s.readTaskFile(t, f.ID, true)
			if err != nil {
				taskFileError(w, err)
				return
			}
		}
		path, err := ex.RestoreUpload(ctx, f.RemoteName, f.Data)
		if err != nil {
			writeErr(w, 502, "Restore stopped: check the connected VPS and conflicting files in uploads/. Saved data is intact. Already copied identical files are safe to retry.")
			return
		}
		restored = append(restored, map[string]any{"name": f.Name, "path": path, "sha256": fileDigest(f.Data)})
	}

	var afterID int64
	for {
		proofs, err := s.m.pg.ForAccount(t.AccountID).TaskExecutionProofsPage(t.AccountID, id, afterID)
		if err != nil {
			writeErr(w, 503, "Execution evidence unavailable; copied files are safe to retry")
			return
		}
		if len(proofs) == 0 {
			break
		}
		afterID = proofs[len(proofs)-1].ID
		evidence, err := json.Marshal(map[string]any{"task_id": t.ID, "traffic_capture": "unavailable", "proofs": proofs, "note": "Original execution evidence; copying does not create or verify a new execution."})
		if err != nil || len(evidence) > 20<<20 {
			writeErr(w, 413, "Evidence page exceeds the 20 MiB export limit; saved evidence remains in Vulnetic")
			return
		}
		name := fmt.Sprintf("vulnetic-evidence-%d-%s.json", proofs[0].ID, fileDigest(evidence)[:16])
		path, err := ex.RestoreUpload(ctx, name, evidence)
		if err != nil {
			writeErr(w, 502, "Evidence restore stopped; check the connected VPS. Saved data is intact; identical copies are safe to retry.")
			return
		}
		restored = append(restored, map[string]any{"name": "Execution evidence", "path": path, "sha256": fileDigest(evidence)})
	}
	detail, _ := json.Marshal(map[string]any{"ssh_target_id": *bound, "files": restored})
	if _, err = t.Store.AppendActivity(db.Activity{Worker: "system", Kind: "text", Summary: "Task files restored to the selected VPS; original execution evidence preserved", Detail: string(detail)}); err != nil {
		writeErr(w, 503, "Files copied, but history could not be saved; retry to confirm the restore")
		return
	}
	writeJSON(w, 200, map[string]any{"ssh_target_id": *bound, "restored": restored})
}

func (s *Server) persistTaskUploads(t *Task, r *http.Request) ([]taskFile, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxChatUpload)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return nil, errTaskFileSize
	}
	defer r.MultipartForm.RemoveAll()
	headers := r.MultipartForm.File["file"]
	if len(headers) == 0 {
		return nil, errors.New("select a file to upload")
	}
	out := make([]taskFile, 0, len(headers))
	for _, header := range headers {
		if !validTaskFileName(header.Filename) {
			return nil, errors.New("invalid file name")
		}
		source, err := header.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(source, 20<<20+1))
		source.Close()
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		f := taskFile{ID: id, Name: header.Filename, RemoteName: id + "-" + header.Filename, Size: int64(len(data)), SHA256: fileDigest(data), CreatedAt: time.Now().UTC()}
		if err = s.saveTaskFile(t, f, data); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}
func (s *Server) uploadTaskFiles(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	if config.SaaSMode() {
		files, err := s.uploadRemoteTaskFiles(w, r, t)
		if err != nil {
			remoteUploadError(w, err)
			return
		}
		writeJSON(w, 201, map[string]any{"files": files})
		return
	}
	files, err := s.persistTaskUploads(t, r)
	if err != nil {
		if errors.Is(err, artifactquota.ErrExceeded) || errors.Is(err, errTaskFileSize) {
			taskFileError(w, err)
		} else {
			writeErr(w, 400, "Upload could not be saved; check the file name, 20 MiB limit and storage availability. Earlier saved files remain in Vulnetic.")
		}
		return
	}
	writeJSON(w, 201, map[string]any{"files": files})
}
func (s *Server) remoteTaskChatUpload(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.URL.Query().Get("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)
	files, err := s.uploadRemoteTaskFiles(w, r, t)
	if err != nil {
		remoteUploadError(w, err)
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, f := range files {
		attachment := chatAttachment{Name: f.Name, Path: f.RemotePath, Abs: f.RemotePath, Size: f.Size}
		attachment.Token = s.attachmentToken(t.AccountID, f.ExecutorID, attachment)
		out = append(out, attachment)
	}
	writeJSON(w, 200, map[string]any{"attachments": out})
}
func (s *Server) promoteTaskDraft(t *Task, draftID string) error {
	draft := &Task{AccountID: t.AccountID, ID: "draft-" + draftID}
	files, err := s.listTaskFiles(draft)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("draft has no saved files")
	}
	for _, f := range files {
		if f.Kind == "remote-upload" {
			bound := t.lifecycleSnapshot().SSHTargetID
			if bound == nil || *bound != f.ExecutorID {
				return errors.New("upload belongs to another executor; upload the file again on the selected executor")
			}
			if err = s.saveTaskFile(t, f, nil); err != nil {
				return err
			}
			continue
		}
		saved, err := s.readTaskFile(draft, f.ID, true)
		if err != nil {
			return err
		}
		if err = s.saveTaskFile(t, saved, saved.Data); err != nil {
			return err
		}
	}
	root, err := s.taskFileRoot(t.AccountID, draft.ID)
	if err == nil {
		defer root.Close()
		for _, f := range files {
			_ = root.Remove(filepath.Join("task-files", draft.ID, f.ID+".vlt"))
		}
	}

	return nil
}

func (s *Server) savedTaskReport(t *Task) (string, error) {
	md, err := s.taskReport(t)
	if err != nil {
		return "", err
	}
	lines := strings.Split(md, "\n")
	canonical := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(line, "- **Generated at**:") {
			canonical = append(canonical, line)
		}
	}
	id := uuid.NewSHA1(uuid.Nil, []byte(strings.Join(canonical, "\n"))).String()
	existing, err := s.readTaskFile(t, id, true)
	if err == nil {
		return string(existing.Data), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f := taskFile{ID: id, Name: "report-" + id + ".md", Kind: "report", RemoteName: "vulnetic-report-" + id + ".md"}
	if err = s.saveTaskFile(t, f, []byte(md)); err != nil {
		return "", err
	}
	return md, nil
}

// The background worker buffers only the small final result, never file contents.
type taskFileRestoreReply struct {
	header http.Header
	status int
	bytes.Buffer
}

func (r *taskFileRestoreReply) Header() http.Header         { return r.header }
func (r *taskFileRestoreReply) WriteHeader(status int)      { r.status = status }
func (r *taskFileRestoreReply) Write(p []byte) (int, error) { return r.Buffer.Write(p) }
