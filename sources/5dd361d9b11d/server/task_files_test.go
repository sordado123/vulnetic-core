package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testTaskFilesRecovery(t *testing.T, s *Server, base string, client *http.Client, task *Task, token, foreign string) {
	t.Helper()
	path := "/api/tasks/" + task.ID + "/files"
	request := func(method, url, auth, contentType string, body io.Reader, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, base+url, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+auth)
		if strings.Contains(url, "stream=1") {
			req.Header.Set("Accept", "application/x-ndjson")
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if method == "POST" && strings.HasSuffix(url, "/files/restore") && response.StatusCode == 202 && want != 202 {
			for attempt := 0; attempt < 200; attempt++ {
				time.Sleep(25 * time.Millisecond)
				statusReq, _ := http.NewRequest("GET", base+url, nil)
				statusReq.Header.Set("Authorization", "Bearer "+auth)
				poll, err := client.Do(statusReq)
				if err != nil {
					t.Fatal(err)
				}
				payload, _ := io.ReadAll(poll.Body)
				poll.Body.Close()
				var state taskFileRestoreState
				if json.Unmarshal(payload, &state) != nil {
					t.Fatal("invalid restore status")
				}
				if state.Status == "restoring" {
					continue
				}
				if state.Status == "done" {
					if want != 200 {
						t.Fatalf("restore succeeded, expected %d", want)
					}
					return payload
				}
				if state.Status == "failed" {
					if want < 400 {
						t.Fatal("restore failed", state.Error)
					}
					return payload
				}
				t.Fatal("restore status lost")
			}
			t.Fatal("restore did not finish")
		}

		if response.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, url, response.StatusCode, want, data)
		}
		return data
	}
	upload := func(auth, name, content string, want int) []byte {
		t.Helper()
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		file, err := form.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.Write([]byte(content))
		_ = form.Close()
		return request("POST", path, auth, form.FormDataContentType(), &body, want)
	}
	request("GET", path, foreign, "", nil, 404)
	upload(foreign, "foreign.txt", "foreign", 404)
	request("POST", path+"/restore", foreign, "", nil, 404)
	request("GET", path+"/restore", foreign, "", nil, 404)
	request("DELETE", path+"/restore", foreign, "", nil, 404)
	// Old encrypted attachments remain downloadable and restorable; new uploads are executor-only.
	saved := taskFile{ID: uuid.NewString(), Name: "input.txt", RemoteName: "old-input-fixture.txt"}
	if err := s.saveTaskFile(task, saved, []byte("saved input fixture")); err != nil {
		t.Fatal(err)
	}
	uploaded := upload(token, "new-input.txt", "executor-only input fixture", 201)
	var result struct {
		Files []taskFile `json:"files"`
	}
	if err := json.Unmarshal(uploaded, &result); err != nil || len(result.Files) != 1 {
		t.Fatal("saved upload missing", err)
	}
	remote := result.Files[0]
	if remote.Kind != "remote-upload" || !strings.Contains(remote.RemotePath, "/temp/uploads/") || remote.Size != int64(len("executor-only input fixture")) {
		t.Fatalf("remote metadata: %+v", remote)
	}
	request("GET", path+"/"+remote.ID, token, "", nil, 404)
	if _, err := s.readTaskFile(task, remote.ID, true); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("remote upload unexpectedly downloadable", err)
	}
	manifest, err := s.remoteAttachmentManifest(task, remote.ExecutorID)
	if err != nil || len(manifest) != 1 || manifest[0].Path != remote.RemotePath {
		t.Fatal("agent cannot locate remote input", err)
	}
	req := llm.CompletionRequest{System: []string{"original system prompt"}}
	if err := (&taskLLMRuntime{s: s, taskID: task.ID}).attachRemoteFiles(&req); err != nil || len(req.System) != 2 || !strings.Contains(req.System[1], remote.RemotePath) || !strings.Contains(req.System[1], "do not print secret contents") {
		t.Fatal("worker input manifest missing", err)
	}
	wrongManifest, err := s.remoteAttachmentManifest(task, remote.ExecutorID+1)
	if err != nil || len(wrongManifest) != 0 {
		t.Fatal("attachment leaked to replacement executor", err)
	}
	remoteBlob, err := os.ReadFile(filepath.Join(s.m.dir, "accounts", fmt.Sprint(task.AccountID), "task-files", task.ID, remote.ID+".vlt"))
	if err != nil || len(remoteBlob) > 4096 {
		t.Fatal("raw remote upload stored in platform", err)
	}
	storage := filepath.Join(s.m.dir, "accounts", fmt.Sprint(task.AccountID), "task-files", task.ID, saved.ID+".vlt")
	sealed, err := os.ReadFile(storage)
	if err != nil || bytes.Contains(sealed, []byte("saved input fixture")) || bytes.Contains(sealed, []byte("input.txt")) {
		t.Fatal("plaintext upload on disk", err)
	}
	request("GET", path+"/"+saved.ID, foreign, "", nil, 404)
	if string(request("GET", path+"/"+saved.ID, token, "", nil, 200)) != "saved input fixture" {
		t.Fatal("download bytes changed")
	}
	if _, err = s.readTaskFile(&Task{ID: task.ID + "9", AccountID: task.AccountID}, saved.ID, true); err == nil {
		t.Fatal("cross-task lookup succeeded")
	}
	if err = s.saveTaskFile(task, taskFile{ID: uuid.NewString(), Name: "../escape", RemoteName: "safe"}, nil); err == nil {
		t.Fatal("unsafe file name accepted")
	}
	if err = s.saveTaskFile(task, taskFile{ID: uuid.NewString(), Name: "large", RemoteName: "large"}, make([]byte, (20<<20)+1)); err == nil {
		t.Fatal("oversized upload accepted")
	}
	// Ownership is authenticated inside the envelope, not inferred from its filename.
	swapped := filepath.Join(filepath.Dir(storage), uuid.NewString()+".vlt")
	if err = os.WriteFile(swapped, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	swappedID := strings.TrimSuffix(filepath.Base(swapped), ".vlt")
	request("GET", path+"/"+swappedID, token, "", nil, 503)
	_ = os.Remove(swapped)
	damaged := append([]byte(nil), sealed...)
	damaged[len(damaged)-1] ^= 1
	if err = os.WriteFile(storage, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	request("GET", path+"/"+saved.ID, token, "", nil, 503)
	request("POST", path+"/restore", token, "", nil, 503)
	if err = os.WriteFile(storage, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	// Legacy platform copies are imported without contacting the deleted VPS.
	legacy := filepath.Join(s.m.dir, "accounts", fmt.Sprint(task.AccountID), "artifacts", "tasks", task.ID, "uploads")
	if err = os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(legacy, "old-input.txt"), []byte("legacy fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	listing := request("GET", path, token, "", nil, 200)
	if !bytes.Contains(listing, []byte("old-input.txt")) {
		t.Fatal("legacy upload not imported")
	}
	if _, err = os.Stat(filepath.Join(legacy, "old-input.txt")); !os.IsNotExist(err) {
		t.Fatal("plaintext legacy copy retained", err)
	}
	// A paused task keeps execution, reassignment and another restore excluded during transfer.
	if err = s.beginTaskFileRestore(task); err != nil {
		t.Fatal(err)
	}
	if err = s.validateSaaSTask(task); err == nil {
		t.Fatal("restore did not exclude execution")
	}
	request("POST", path+"/restore", token, "", nil, 409)
	request("PUT", "/api/tasks/"+task.ID+"/ssh-target", token, "application/json", strings.NewReader(fmt.Sprintf(`{"ssh_target_id":%d}`, *task.lifecycleSnapshot().SSHTargetID)), 409)
	s.taskFileRestores.Delete(task.ID)
	s.engine.decInflight(task.ID)
	firstReport := request("GET", "/api/report?task="+task.ID, token, "", nil, 200)
	secondReport := request("GET", "/api/report?task="+task.ID, token, "", nil, 200)
	if !bytes.Equal(firstReport, secondReport) {
		t.Fatal("unchanged report was duplicated")
	}

	restored := request("POST", path+"/restore", token, "", nil, 200)
	var recovery struct {
		Restored []struct{ Name, Path, SHA256 string } `json:"restored"`
	}
	if json.Unmarshal(restored, &recovery) != nil || len(recovery.Restored) != 4 {
		t.Fatal("uploads, report or evidence missing", string(restored))
	}
	ex := s.agentsForTask(task).sshExecutor
	for _, f := range recovery.Restored {
		if !strings.Contains(f.Path, "/tasks/"+task.ID+"/uploads/") {
			t.Fatal("wrong restored workspace", f.Path)
		}
		var out bytes.Buffer
		command, err := ex.Start(t.Context(), "", nil, "sha256sum "+"'"+strings.ReplaceAll(f.Path, "'", "'\"'\"'")+"'", &out)
		if err != nil {
			t.Fatal(err)
		}
		if err = command.Wait(); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(out.String(), f.SHA256) {
			t.Fatal("restored checksum differs")
		}
	}
	if _, err = ex.RestoreUpload(t.Context(), "odd'file;name.txt", []byte("quoted file")); err != nil {
		t.Fatal("quoted filename failed", err)
	}

	// Same bytes can be retried, but an existing different file must never be overwritten.
	request("POST", path+"/restore", token, "", nil, 200)
	var out bytes.Buffer
	command, err := ex.Start(t.Context(), "", nil, "printf conflict > uploads/"+saved.RemoteName, &out)
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Wait(); err != nil {
		t.Fatal(err)
	}
	request("POST", path+"/restore", token, "", nil, 502)
	if string(request("GET", path+"/"+saved.ID, token, "", nil, 200)) != "saved input fixture" {
		t.Fatal("central copy changed after failed restore")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = ex.RestoreUpload(ctx, "cancelled-fixture", []byte("cancel")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled restore was not stopped", err)
	}
	var ignored bytes.Buffer
	command, err = ex.Start(t.Context(), "", nil, "ln -s /etc/hosts uploads/symlink-fixture", &ignored)
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err = ex.RestoreUpload(t.Context(), "symlink-fixture", []byte("no symlink")); err == nil {
		t.Fatal("remote symlink destination accepted")
	}
	accountRoot, err := s.taskFileRoot(task.AccountID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	quota, err := accountRoot.OpenFile("quota-fixture", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = quota.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	quota.Close()
	artifactquota.Invalidate(accountRoot) // The fixture changed the tree outside the quota writer.
	// A full platform quota also prevents saving attachment metadata; file bytes remain remote.
	if err := s.saveTaskFile(task, taskFile{ID: uuid.NewString(), Name: "quota-proof.txt", RemoteName: "quota-proof.txt"}, []byte("blocked")); !errors.Is(err, artifactquota.ErrExceeded) {
		t.Fatal("platform artifact quota not enforced", err)
	}
	upload(token, "quota-input.txt", "remote-only input", 413)
	_ = artifactquota.Remove(accountRoot, "quota-fixture")
	accountRoot.Close()
	if string(request("GET", path+"/"+saved.ID, token, "", nil, 200)) != "saved input fixture" {
		t.Fatal("quota changed previous data")
	}

	// Task identities are global, but ciphertext still cannot be moved between tasks or accounts.
	other := &Task{ID: task.ID + "9", AccountID: task.AccountID}
	otherRoot, err := s.taskFileRoot(other.AccountID, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = replaceRootBytes(otherRoot, filepath.Join("task-files", other.ID, saved.ID+".vlt"), sealed); err != nil {
		t.Fatal(err)
	}
	otherRoot.Close()
	if _, err = s.readTaskFile(other, saved.ID, true); err == nil {
		t.Fatal("cross-task ciphertext accepted")
	}
	cancelCtx, cancelJob := context.WithCancel(t.Context())
	defer cancelJob()
	s.taskFileRestoreJobs.Store(task.ID, &taskFileRestoreJob{state: taskFileRestoreState{Status: "restoring"}, cancel: cancelJob})
	request("DELETE", path+"/restore", token, "", nil, 202)
	select {
	case <-cancelCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("restore cancellation did not reach worker")
	}
	s.taskFileRestoreJobs.Delete(task.ID)

	draft := &Task{ID: "draft-fixture", AccountID: task.AccountID}
	draftFile := taskFile{ID: uuid.NewString(), Name: "draft.txt", RemoteName: "draft-fixture.txt"}
	if err = s.saveTaskFile(draft, draftFile, []byte("draft fixture")); err != nil {
		t.Fatal(err)
	}
	if err = s.promoteTaskDraft(task, "fixture"); err != nil {
		t.Fatal(err)
	}
	if f, err := s.readTaskFile(task, draftFile.ID, true); err != nil || string(f.Data) != "draft fixture" {
		t.Fatal("draft not associated with task", err)
	}
	remote.ID = uuid.NewString()
	if err := s.saveTaskFile(draft, remote, nil); err != nil {
		t.Fatal(err)
	}
	wrongTask := &Task{ID: "draft-wrong-target", AccountID: task.AccountID}
	if err := s.promoteTaskDraft(wrongTask, "fixture"); err == nil {
		t.Fatal("draft moved to a different executor")
	}
	if err := s.promoteTaskDraft(task, "fixture"); err != nil {
		t.Fatal(err)
	}
	f, err := s.readTaskFile(task, remote.ID, false)
	if err != nil || f.RemotePath != remote.RemotePath || f.Size != remote.Size {
		t.Fatal("remote draft metadata lost", err)
	}
}

func TestTaskExecutionProofExportPages(t *testing.T) {
	// Reuse the authenticated reverse-agent fixture's database setup independently.
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
			t.Fatal(err)
		}
		t.Skip("PostgreSQL required")
	}
	defer m.Close()
	key := bytes.Repeat([]byte{7}, 32)
	m.pg.ConfigureVault(key, true)
	a, _, err := m.pg.CreateAccountWithAdmin("proof-pages-"+uuid.NewString(), uuid.NewString()+"@example.test", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.pg.CreateTaskWithOptions("proof pages", "fixture", db.TaskCreateOptions{AccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)
	for n := 0; n < 105; n++ {
		if err = m.pg.RecordExecutionProof(t.Context(), db.ExecutionProof{AccountID: a.ID, TaskID: &task.ID, RunID: fmt.Sprint(n), Tool: "fixture", Input: json.RawMessage(`{}`), Output: fmt.Sprint("proof ", n)}); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	var after int64
	for {
		page, err := m.pg.ForAccount(a.ID).TaskExecutionProofsPage(a.ID, task.ID, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 10 {
			t.Fatal("unbounded proof page")
		}
		for _, p := range page {
			if p.ID <= after || p.TaskID == nil || *p.TaskID != task.ID {
				t.Fatal("wrong proof attribution")
			}
			after = p.ID
			count++
		}
	}
	if count != 105 {
		t.Fatalf("exported %d of 105 proofs", count)
	}
	if _, err = m.pg.ForAccount(a.ID+1).TaskExecutionProofsPage(a.ID, task.ID, 0); err == nil {
		t.Fatal("foreign account export allowed")
	}
}
func TestSavedTaskFileDeletionRollsBack(t *testing.T) {
	dataDir := t.TempDir()
	saved := filepath.Join(dataDir, "accounts", "3", "task-files", "77", "fixture.vlt")
	if err := os.MkdirAll(filepath.Dir(saved), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("sealed fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	stage, err := stageTaskFiles(dataDir, "77", 12, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(saved); !os.IsNotExist(err) {
		t.Fatal("saved files were not staged")
	}
	if err = stage.rollback(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(saved); err != nil || string(data) != "sealed fixture" {
		t.Fatal("saved file was not restored", err)
	}
}
