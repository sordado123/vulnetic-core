package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sordado123/vulnetic/internal/artifactquota"
)

// Returning an error instead of EOF stops the remote transfer before it commits an oversized file.
type uploadReader struct {
	r io.Reader
	n int64
}

func (r *uploadReader) Read(p []byte) (int, error) {
	remaining := (20 << 20) + 1 - r.n
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.r.Read(p)
	r.n += int64(n)
	if r.n > 20<<20 {
		return n, errTaskFileSize
	}
	return n, err
}

type attachmentUploader interface {
	Upload(context.Context, string, io.Reader) (string, error)
}

// MultipartReader never spills request bodies to the platform's temporary directory.
func transferRemoteUploads(ctx context.Context, r *http.Request, ex attachmentUploader, targetID int64, save func(taskFile) error) ([]taskFile, error) {
	parts, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("invalid multipart upload")
	}
	out := []taskFile{}
	for {
		part, err := parts.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		_, disposition, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			return nil, errors.New("invalid upload disposition")
		}
		name := disposition["filename"]
		if part.FormName() != "file" || !validTaskFileName(name) || len(name) > 200 || strings.ContainsAny(name, ":*?\"<>|") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
			return nil, errors.New("invalid upload field or file name")
		}
		id := uuid.NewString()
		reader := &uploadReader{r: part}
		hash := sha256.New()
		path, err := ex.Upload(ctx, id+"-"+name, io.TeeReader(reader, hash))
		if reader.n > 20<<20 {
			return nil, errTaskFileSize
		}
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := taskFile{Kind: "remote-upload", ID: id, Name: name, RemoteName: id + "-" + name, RemotePath: path, ExecutorID: targetID, Size: reader.n, SHA256: hex.EncodeToString(hash.Sum(nil)), CreatedAt: time.Now().UTC()}
		if err := save(f); err != nil {
			return nil, fmt.Errorf("file reached the executor, but its metadata could not be saved; no platform copy exists: %w", err)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("select a file to upload")
	}
	return out, nil
}

func (s *Server) streamRemoteUploads(w http.ResponseWriter, r *http.Request, owner *Task, targetID int64, directory string) ([]taskFile, error) {
	ex, closeExecutor, err := s.remoteExecutor(owner.AccountID, targetID, directory)
	if err != nil {
		return nil, &remoteUploadUnavailable{err}
	}
	defer closeExecutor()
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	stopClosingBody := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stopClosingBody()
	return transferRemoteUploads(ctx, r, ex, targetID, func(f taskFile) error { return s.saveTaskFile(owner, f, nil) })
}

func (s *Server) uploadRemoteTaskFiles(w http.ResponseWriter, r *http.Request, t *Task) ([]taskFile, error) {
	bound := t.lifecycleSnapshot().SSHTargetID
	if bound == nil {
		return nil, &remoteUploadUnavailable{errors.New("select a connected task executor before uploading")}
	}
	return s.streamRemoteUploads(w, r, t, *bound, fmt.Sprintf(".vulnetic/accounts/%d/tasks/%s/temp", t.AccountID, t.ID))
}

type remoteUploadUnavailable struct{ error }

func remoteUploadError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	var unavailable *remoteUploadUnavailable
	switch {
	case errors.Is(err, artifactquota.ErrExceeded):
		writeErr(w, 413, "Account metadata storage quota reached; existing files were preserved")
	case errors.Is(err, errTaskFileSize), errors.As(err, &tooLarge):
		writeErr(w, 413, "Upload exceeds the 20 MiB file limit; select a smaller file")
	case errors.As(err, &unavailable):
		writeErr(w, 409, "A connected executor is required to receive uploads")
	default:
		writeErr(w, 502, "Upload was not confirmed. Check the executor and retry. No file copy was saved in Vulnetic; earlier uploads remain on their executor.")
	}
}

func (s *Server) remoteAttachmentManifest(owner *Task, targetID int64) ([]chatAttachment, error) {
	files, err := s.listTaskFiles(owner)
	if err != nil {
		return nil, err
	}
	attachments := []chatAttachment{}
	for _, f := range files {
		if f.Kind == "remote-upload" && f.ExecutorID == targetID {
			attachments = append(attachments, chatAttachment{Name: f.Name, Path: f.RemotePath, Abs: f.RemotePath, Size: f.Size})
		}
	}
	return attachments, nil
}
