package server

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/artifactquota"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20  // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 21 << 20 // 512 MiB per upload request
)

// wsResolve maps a user-supplied relative path to an absolute path INSIDE the work
// dir. It returns ok=false if the path would escape the root. filepath.Clean on a
// rooted copy collapses any ".." so nothing can climb above the root.
func (s *Server) wsResolve(rel string) (string, bool) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ".", true
	}
	if !filepath.IsLocal(rel) {
		return "", false
	}
	return filepath.Clean(rel), true
}
func (s *Server) wsRel(rel string) string {
	if rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}
func (s *Server) workspaceRoot(w http.ResponseWriter, r *http.Request) (*os.Root, bool) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return nil, false
	}
	// Only account artifacts are exposed, never the server workspace or its keys.
	base, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 503, "Workspace unavailable")
		return nil, false
	}
	defer base.Close()
	name := filepath.Join("accounts", fmt.Sprint(accountID), "artifacts")
	if err = base.MkdirAll(name, 0700); err != nil {
		writeErr(w, 503, "Workspace unavailable")
		return nil, false
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		writeErr(w, 503, "Workspace unavailable")
		return nil, false
	}
	return root, true
}
func rootReadDir(root *os.Root, name string) ([]os.DirEntry, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}
func workspaceBytes(root *os.Root) (int64, error) {
	var total int64
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
func workspaceQuota(root *os.Root, name string, size int64) error {
	account, err := os.OpenRoot(filepath.Dir(root.Name()))
	if err != nil {
		return err
	}
	defer account.Close()
	if err := checkArtifactQuota(0, size); err != nil {
		return err
	}
	return artifactquota.Check(account, filepath.Join(filepath.Base(root.Name()), name), size)
}

func checkArtifactQuota(total, size int64) error {
	if size < 0 || size > 20<<20 {
		return fmt.Errorf("file exceeds the 20 MiB limit")
	}
	if total+size > 1<<30 {
		return fmt.Errorf("account artifact quota of 1 GiB exceeded")
	}
	return nil
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	fi, err := root.Stat(abs)
	if err != nil {
		writeErr(w, 404, "path does not exist")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "not a directory")
		return
	}
	ents, err := rootReadDir(root, abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  s.wsRel(filepath.Join(abs, e.Name())),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// Directories first, each sorted by name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	fi, err := root.Stat(abs)
	if err != nil {
		writeErr(w, 404, "file does not exist")
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, "is a directory, cannot be read as a file")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := root.ReadFile(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)

	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == "." {
		writeErr(w, 400, "invalid path")
		return
	}
	if fi, err := root.Stat(abs); err == nil && fi.IsDir() {
		writeErr(w, 400, "target is a directory")
		return
	}
	if err := root.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := workspaceQuota(root, abs, int64(len(req.Content))); err != nil {
		writeErr(w, 413, err.Error())
		return
	}
	if err := saveRootBytes(root, abs, []byte(req.Content)); err != nil {
		status := 500
		if errors.Is(err, artifactquota.ErrExceeded) {
			status = 413
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

func saveRootBytes(root *os.Root, dest string, data []byte) error {
	if err := checkArtifactQuota(0, int64(len(data))); err != nil {
		return err
	}
	account, err := os.OpenRoot(filepath.Dir(root.Name()))
	if err != nil {
		return err
	}
	defer account.Close()
	return artifactquota.Write(account, filepath.Join(filepath.Base(root.Name()), dest), int64(len(data)), false, func() error { return replaceRootBytes(root, dest, data) })
}

func replaceRootBytes(root *os.Root, dest string, data []byte) error {
	name := ".write-" + uuid.NewString()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(name, dest)
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == "." {
		writeErr(w, 400, "invalid path")
		return
	}
	if err := root.MkdirAll(abs, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	if abs == "." {
		writeErr(w, 400, "cannot delete the workspace root directory")
		return
	}
	if _, err := root.Stat(abs); err != nil {
		writeErr(w, 404, "path does not exist")
		return
	}
	account, err := os.OpenRoot(filepath.Dir(root.Name()))
	if err != nil {
		writeErr(w, 503, "Storage unavailable")
		return
	}
	defer account.Close()
	if err := artifactquota.RemoveAll(account, filepath.Join(filepath.Base(root.Name()), abs)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	fi, err := root.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "file does not exist")
		return
	}
	name := filepath.Base(abs)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	file, err := root.Open(abs)
	if err != nil {
		writeErr(w, 404, "file not found")
		return
	}
	defer file.Close()
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	if config.SaaSMode() {
		writeErr(w, 409, "Upload inputs through chat or Task files with a connected executor; new workspace uploads are disabled")
		return
	}
	root, authorized := s.workspaceRoot(w, r)
	if !authorized {
		return
	}
	defer root.Close()

	dirAbs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	if fi, err := root.Stat(dirAbs); err != nil || !fi.IsDir() {
		writeErr(w, 400, "target directory does not exist")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "failed to parse upload or size limit exceeded: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destAbs, okd := s.wsResolve(filepath.Join(s.wsRel(dirAbs), name))
		if !okd {
			continue
		}
		if err := workspaceQuota(root, destAbs, hdr.Size); err != nil {
			writeErr(w, 413, err.Error())
			return
		}
		if err := saveRootUpload(root, hdr, destAbs); err != nil {
			status := 500
			if errors.Is(err, artifactquota.ErrExceeded) {
				status = 413
			}
			writeErr(w, status, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}

func saveRootUpload(root *os.Root, hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, (20<<20)+1))
	if err != nil {
		return err
	}
	return saveRootBytes(root, dest, data)
}
