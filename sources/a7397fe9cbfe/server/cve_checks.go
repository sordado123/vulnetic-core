package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/cvecheck"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/intercept"
	actool "github.com/sordado123/vulnetic/internal/norma/tool"
	"github.com/sordado123/vulnetic/internal/platformpolicy"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func (s *Server) cveVerificationInfo(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "Task not found")
		return
	}
	id, err := parseTaskID(t.ID)
	if err != nil {
		writeErr(w, 404, "Task not found")
		return
	}
	pg := s.m.pg.ForAccount(t.AccountID)
	runs, err := pg.CVEChecks(t.AccountID, id)
	if err != nil {
		writeErr(w, 503, "Verification history unavailable")
		return
	}
	rows, err := pg.Query(`SELECT id,url FROM assets WHERE account_id=$1 AND $2=ANY(task_ids) AND url IS NOT NULL AND url<>'' ORDER BY id LIMIT 100`, t.AccountID, id)
	if err != nil {
		writeErr(w, 503, "Assets unavailable")
		return
	}
	defer rows.Close()
	assets := []map[string]any{}
	for rows.Next() {
		var id int64
		var raw string
		if rows.Scan(&id, &raw) != nil {
			writeErr(w, 503, "Assets unavailable")
			return
		}
		u, e := url.Parse(raw)
		if e == nil && u.Hostname() != "" && u.User == nil && (u.Path == "" || u.Path == "/") {
			assets = append(assets, map[string]any{"id": id, "url": raw})
		}
	}
	if rows.Err() != nil {
		writeErr(w, 503, "Assets unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"catalogue": cvecheck.Catalogue(), "assets": assets, "runs": runs, "laboratory_mode": os.Getenv("VULNETIC_CVE_LAB_MODE") == "true", "traffic_capture": "unavailable"})
}
func (s *Server) authorizeCVEVerification(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "Task not found")
		return
	}
	accountID, userID, ok := accountFromContext(r.Context())
	if !ok || userID <= 0 {
		writeErr(w, 401, "Authenticated user required")
		return
	}
	var input struct {
		AssetID   int64             `json:"asset_id"`
		RecipeID  string            `json:"recipe_id"`
		CanaryID  string            `json:"canary_id"`
		Token     string            `json:"token"`
		Headers   map[string]string `json:"headers"`
		Confirmed bool              `json:"confirmed"`
	}
	if !decodeConversationRequest(w, r, &input) {
		return
	}
	if !input.Confirmed {
		writeErr(w, 422, "Explicit authorization and target-side canary setup are required")
		return
	}
	recipe, err := cvecheck.Lookup(input.RecipeID)
	if err != nil {
		writeErr(w, 422, "Verifier unsupported")
		return
	}
	if recipe.LaboratoryOnly && os.Getenv("VULNETIC_CVE_LAB_MODE") != "true" {
		writeErr(w, 409, "Verifier is restricted to isolated laboratory validation")
		return
	}
	targetID := t.lifecycleSnapshot().SSHTargetID
	if targetID == nil {
		writeErr(w, 409, "Connect the task VPS before authorizing verification")
		return
	}
	if _, err = s.verifiedTarget(accountID, *targetID); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	assets, err := s.m.pg.ForAccount(accountID).Assets().GetByIDs([]int64{input.AssetID})
	if err != nil || len(assets) != 1 {
		writeErr(w, 404, "Asset not found")
		return
	}
	target := cvecheck.Target{URL: assets[0].URL, CanaryID: input.CanaryID, Token: input.Token, ControlPath: "/vulnetic-control/" + input.CanaryID + ".txt", Headers: input.Headers}
	if err = target.Validate(); err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	if err = platformpolicy.CheckHost(target.URL); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	taskID, _ := parseTaskID(t.ID)
	a, err := s.m.pg.CreateCVEAuthorization(r.Context(), db.CVEAuthorization{AccountID: accountID, UserID: userID, TaskID: taskID, AssetID: input.AssetID, ExecutorID: *targetID, RecipeID: recipe.ID, RecipeDigest: recipe.Digest(), TargetURL: target.URL, Target: target, RemainingRuns: 1})
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}

	writeJSON(w, 201, a)
}
func (s *Server) executeCVEVerification(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "Task not found")
		return
	}
	accountID, userID, ok := accountFromContext(r.Context())
	if !ok {
		writeErr(w, 401, "Authentication required")
		return
	}
	var input struct {
		AuthorizationID int64 `json:"authorization_id"`
	}
	if !decodeConversationRequest(w, r, &input) {
		return
	}
	taskID, _ := parseTaskID(t.ID)
	result, err := s.runAuthorizedCVECheck(r.Context(), accountID, userID, taskID, input.AuthorizationID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) runAuthorizedCVECheck(ctx context.Context, accountID, userID, taskID, authorizationID int64) (*db.CVECheckRun, error) {
	if accountID <= 0 || userID <= 0 || taskID <= 0 {
		return nil, fmt.Errorf("authenticated task execution required")
	}
	a, err := s.m.pg.CVEAuthorization(ctx, accountID, authorizationID)
	if err != nil || a.TaskID != taskID {
		return nil, fmt.Errorf("authorization not found")
	}
	recipe, err := cvecheck.Lookup(a.RecipeID)
	if err != nil || recipe.Digest() != a.RecipeDigest {
		return nil, fmt.Errorf("verifier changed; authorize again")
	}
	if recipe.LaboratoryOnly && os.Getenv("VULNETIC_CVE_LAB_MODE") != "true" {
		return nil, fmt.Errorf("verifier is laboratory-only")
	}
	if err = platformpolicy.CheckHost(a.TargetURL); err != nil {
		return nil, err
	}
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task.AccountID != accountID {
		return nil, fmt.Errorf("task unavailable")
	}
	current := task.lifecycleSnapshot().SSHTargetID
	if current == nil || *current != a.ExecutorID {
		return nil, fmt.Errorf("executor changed; authorize the new VPS")
	}
	ex, closeExecutor, err := s.remoteExecutor(accountID, a.ExecutorID, fmt.Sprintf(".vulnetic/accounts/%d/tasks/%d", accountID, taskID))
	if err != nil {
		return nil, err
	}
	defer closeExecutor()
	run, a, err := s.m.pg.StartCVECheck(ctx, accountID, userID, authorizationID, taskID)
	if err != nil {
		return nil, err
	}
	// Every exit settles the persistent slot, including request cancellation or failed evidence storage.
	finished := false
	defer func() {
		if !finished {
			end, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			failure := cvecheck.Result{RecipeID: run.RecipeID, RecipeDigest: run.RecipeDigest, Target: run.TargetURL, Outcome: "inconclusive", Reason: "execution interrupted or evidence could not be committed"}
			_ = s.m.pg.FinishCVECheck(end, run, failure, nil)
		}
	}()
	transport := &http.Transport{DialContext: ex.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	runner, err := cvecheck.NewRunner(&http.Client{Transport: transport}, func() error {
		current, e := s.m.pg.ForAccount(accountID).GetTask(taskID)
		if e != nil || current == nil || current.SSHTargetID == nil || *current.SSHTargetID != a.ExecutorID {
			return errors.New("task executor binding changed")
		}
		_, err := s.verifiedTarget(accountID, a.ExecutorID)
		if err != nil {
			return err
		}
		target, err := s.m.pg.CVEAuthorization(ctx, accountID, a.ID)
		if err != nil || time.Now().After(target.ExpiresAt) {
			return errors.New("authorization expired")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := runner.Run(ctx, recipe, a.Target)
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	input, _ := json.Marshal(map[string]any{"authorization_id": a.ID, "recipe_id": recipe.ID, "recipe_digest": recipe.Digest(), "target": a.Target})
	proof := db.ExecutionProof{AccountID: accountID, UserID: userID, TaskID: &taskID, AssetID: &a.AssetID, ExecutorID: &a.ExecutorID, VerificationRunID: &run.ID, RunID: fmt.Sprintf("cve-check-%d", run.ID), Tool: "verify_cve_candidate", Input: input, Output: string(raw)}
	if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
		proof.ConversationID = &convID
	}
	end, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	proofID, err := s.persistProof(end, proof)
	if err != nil {
		s.evidenceFailures.Add(1)
		return nil, fmt.Errorf("execution evidence could not be committed")
	}
	if err = s.m.pg.FinishCVECheck(end, run, result, &proofID); err != nil {
		return nil, err
	}
	finished = true
	if err = s.m.pg.RecordAudit(accountID, userID, "CVE_EXECUTE", fmt.Sprintf("/cve-checks/%d", run.ID), 200); err != nil {
		return nil, fmt.Errorf("execution completed but audit unavailable")
	}
	runs, err := s.m.pg.CVEChecks(accountID, taskID)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		if r.ID == run.ID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("committed result unavailable")
}
func (s *Server) cveVerificationTools() []actool.CoreTool {
	return []actool.CoreTool{roTool("list_cve_verifiers", "List operator-reviewed CVE verifier capabilities. Candidates or laboratory success never confirm the customer's target.", objSchema(nil), func(context.Context, json.RawMessage) (actool.Result, error) {
		return jsonResult(map[string]any{"catalogue": cvecheck.Catalogue()})
	}), wrTool("verify_cve_candidate", "Execute one exact verifier authorization already approved by the authenticated customer. Cannot create approval, choose another account/target/VPS or change the verifier. Records controls and complete evidence; does not confirm or close a finding.", objSchema(map[string]any{"authorization_id": map[string]any{"type": "integer"}}, "authorization_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var input struct {
			AuthorizationID int64 `json:"authorization_id"`
		}
		if json.Unmarshal(in, &input) != nil {
			return actool.Errorf("Invalid authorization"), nil
		}
		ri := agent.RunInfoFrom(ctx)
		if ri.AccountID <= 0 || ri.TaskID <= 0 || ri.UserID <= 0 || ri.ExecutorID <= 0 {
			return actool.Errorf("authenticated task and session VPS are required"), nil
		}
		authorization, err := s.m.pg.CVEAuthorization(ctx, ri.AccountID, input.AuthorizationID)
		if err != nil || ri.ExecutorID != authorization.ExecutorID {
			return actool.Errorf("authorization does not match this session's VPS"), nil
		}
		result, err := s.runAuthorizedCVECheck(ctx, ri.AccountID, ri.UserID, ri.TaskID, input.AuthorizationID)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(result)
	})}
}
func (s *Server) seedCVEVerificationTools(pg *db.DB) error {
	for _, t := range s.cveVerificationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := pg.SeedTool(t.Name(), t.Description(), schema, json.RawMessage(`["worker","pentest","auto","retester"]`)); err != nil {
			return err
		}
	}
	return nil
}
