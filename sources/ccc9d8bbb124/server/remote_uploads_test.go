package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type fixtureUploader struct {
	bytes int64
	fail  error
}

func (u *fixtureUploader) Upload(ctx context.Context, name string, r io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if u.fail != nil {
		return "", u.fail
	}
	n, err := io.Copy(io.Discard, r)
	u.bytes = n
	return "C:/Vulnetic/workspace/temp/uploads/" + name, err
}

func uploadFixture(t *testing.T, name string, size int) *http.Request {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	p, err := form.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyN(p, strings.NewReader(strings.Repeat("x", size)), int64(size)); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/chat/upload", &body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	return r
}

func TestRemoteUploadsStreamWithoutPlatformFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMPDIR", tmp)
	for _, size := range []int{0, 7, 2 << 20, 20 << 20} {
		t.Run(humanBytes(int64(size)), func(t *testing.T) {
			u := &fixtureUploader{}
			r := uploadFixture(t, "id_ed25519", size)
			var saved []taskFile
			files, err := transferRemoteUploads(t.Context(), r, u, 42, func(f taskFile) error { saved = append(saved, f); return nil })
			if err != nil || len(files) != 1 || len(saved) != 1 {
				t.Fatalf("upload: %v %+v", err, files)
			}
			f := files[0]
			if f.Size != int64(size) || u.bytes != int64(size) || f.Kind != "remote-upload" || f.ExecutorID != 42 || len(f.Data) != 0 || !strings.Contains(f.RemotePath, "/temp/uploads/") {
				t.Fatalf("metadata: %+v", f)
			}
			if r.MultipartForm != nil && (len(r.MultipartForm.File) != 0 || len(r.MultipartForm.Value) != 0) {
				t.Fatal("upload parsed into a spillable multipart form")
			}
		})
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("platform temporary files: %v %v", entries, err)
	}
}

func TestRemoteUploadsRejectOversizeUnsafeAndFailedTransfers(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		fail error
	}{
		{"too-large", 20<<20 + 1, nil}, {"bad:name", 1, nil}, {`..\escape`, 1, nil}, {"offline", 1, errors.New("disconnected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := transferRemoteUploads(t.Context(), uploadFixture(t, tc.name, tc.size), &fixtureUploader{fail: tc.fail}, 42, func(taskFile) error { called = true; return nil })
			if err == nil || called {
				t.Fatalf("unsafe or incomplete upload saved: %v", err)
			}
			if tc.size > 20<<20 && !errors.Is(err, errTaskFileSize) {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := transferRemoteUploads(ctx, uploadFixture(t, "cancel", 1), &fixtureUploader{}, 42, func(taskFile) error { t.Fatal("cancelled upload saved"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{errTaskFileSize, 413}, {&http.MaxBytesError{Limit: maxChatUpload}, 413}, {&remoteUploadUnavailable{errors.New("offline")}, 409}, {errors.New("transfer failed"), 502}} {
		w := httptest.NewRecorder()
		remoteUploadError(w, tc.err)
		if w.Code != tc.status {
			t.Fatalf("status %d, wanted %d", w.Code, tc.status)
		}
	}
}

func TestSaaSWorkspaceUploadDoesNotPersist(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	w := httptest.NewRecorder()
	(&Server{}).wsUpload(w, uploadFixture(t, "input.txt", 7))
	if w.Code != 409 {
		t.Fatalf("workspace upload accepted: %d", w.Code)
	}
}
