package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/sidequestion"
)

// The runtime variant replaces the root DB, not only the request middleware pool.
func TestAccountRuntimeRegression(t *testing.T) {
	for _, runtimeOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime_%t", runtimeOnly), func(t *testing.T) {
			dsn, _, err := db.DSN()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			parsed.Path = fmt.Sprintf("/vulnetic_account_regression_%d", time.Now().UnixNano())
			t.Setenv("VULNETIC_PG_DSN", parsed.String())
			t.Setenv("VULNETIC_SAAS_MODE", "false")
			password := ""
			if runtimeOnly {
				password = "account-regression-fixture-only"
			}
			t.Setenv("VULNETIC_PG_APP_PASSWORD", password)
			m, err := NewManager(t.TempDir(), "")
			if err != nil {
				if os.Getenv("VULNETIC_REQUIRE_PG_TESTS") == "true" {
					t.Fatal(err)
				}
				t.Skip("PostgreSQL required")
			}
			operator := m.pg
			t.Cleanup(func() { _ = operator.Close() })
			if runtimeOnly {
				appDSN, err := config.PostgresAppDSN()
				if err != nil {
					t.Fatal(err)
				}
				m.pg, err = db.OpenRuntime(appDSN)
				if err != nil {
					t.Fatal(err)
				}
				m.assets = m.pg.Assets()
			}
			t.Cleanup(func() { _ = m.Close() })
			t.Setenv("VULNETIC_SAAS_MODE", "true")
			ctx, cancel := context.WithCancel(t.Context())
			s := &Server{m: m, engine: NewEngine(m), ctx: ctx, jwtKey: []byte("account-runtime-fixture-key-only")}
			s.initSideQuestions()
			t.Cleanup(func() { cancel(); <-s.side.done })
			handler := s.Handler()
			type owner struct {
				account                         db.Account
				task                            *Task
				token                           string
				finding, category, profile, mcp int64
			}
			makeOwner := func(name string) owner {
				t.Helper()
				a, user, err := operator.CreateAccountWithAdmin(name, name+"@fixture.invalid", "fixture", s.seedAccountCatalog)
				if err != nil {
					t.Fatal(err)
				}
				token, err := signJWTForPassword(s.jwtKey, a.ID, user.ID, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				task, err := m.CreateTaskWithOptions(name, "No model calls", db.TaskCreateOptions{AccountID: a.ID, UserID: user.ID})
				if err != nil {
					t.Fatal(err)
				}
				pg := operator.ForAccount(a.ID)
				taskID, _ := strconv.ParseInt(task.ID, 10, 64)
				finding, err := pg.AddFinding(taskID, 0, "fixture-class", name+" finding", "medium", name+" summary", "synthetic evidence", "fixture", nil)
				if err != nil {
					t.Fatal(err)
				}
				category, err := pg.CreateTaskCategory("Same category")
				if err != nil {
					t.Fatal(err)
				}
				profile, err := pg.SaveProfile(&db.LLMProfile{Name: "Same profile", Format: "openai", Model: "fixture", APIKey: "fixture-key", AccountID: a.ID})
				if err != nil {
					t.Fatal(err)
				}
				mcp, err := pg.SaveMCP(&db.MCPServer{AccountID: a.ID, Name: "Same MCP", Transport: "http", URL: "https://fixture.invalid", Env: json.RawMessage(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				return owner{a, task, token, finding, category.ID, profile, mcp}
			}
			a, b := makeOwner("account-a"), makeOwner("account-b")
			req := func(o owner, method, path, body string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, "/api"+path, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+o.token)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			status := func(w *httptest.ResponseRecorder, want int) {
				t.Helper()
				if w.Code != want {
					t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
				}
			}
			t.Run("findings_views_export_and_mutations", func(t *testing.T) {
				for _, path := range []string{"/exploration/findings?page=1&limit=20", "/exploration/findings/groups?page=1&limit=20", "/exploration/findings/asset-tree", "/exploration/findings/export?scope=all&format=json"} {
					w := req(a, "GET", path, "")
					status(w, 200)
					if strings.Contains(w.Body.String(), "account-b") {
						t.Fatalf("foreign finding in %s", path)
					}
					if path != "/exploration/findings/asset-tree" && !strings.Contains(w.Body.String(), "account-a") {
						t.Fatalf("own finding missing in %s: %s", path, w.Body.String())
					}
					if path == "/exploration/findings/asset-tree" && !strings.Contains(w.Body.String(), `"finding_total":1`) {
						t.Fatalf("tree count: %s", w.Body.String())
					}
				}
				path := fmt.Sprintf("/exploration/findings/%d", a.finding)
				status(req(b, "PATCH", path, `{"severity":"low"}`), 404)
				status(req(a, "PATCH", path, `{"name":"owned changed","severity":"low","status":"pending"}`), 200)
				status(req(b, "DELETE", path, ""), 404)
				status(req(a, "DELETE", path, ""), 200)
			})
			t.Run("companies_and_categories", func(t *testing.T) {
				w := req(a, "POST", "/companies", `{"name":"Owned company","scope":["example.test"]}`)
				status(w, 201)
				var created struct {
					ID int64 `json:"id"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
					t.Fatal(err)
				}
				path := fmt.Sprintf("/companies/%d", created.ID)
				status(req(a, "GET", path, ""), 200)
				status(req(b, "GET", path, ""), 404)
				status(req(a, "POST", path+"/scope", `{"scope":["other.example.test"]}`), 200)
				status(req(b, "DELETE", path, ""), 404)
				status(req(a, "DELETE", path, ""), 200)
				path = fmt.Sprintf("/task-categories/%d", a.category)
				status(req(b, "PATCH", path, `{"name":"foreign"}`), 404)
				status(req(a, "PATCH", path, `{"name":"owned"}`), 200)
				status(req(a, "POST", "/tasks/category/batch", fmt.Sprintf(`{"task_ids":[%q],"category_id":%d}`, a.task.ID, a.category)), 200)
				state, err := operator.ForAccount(a.account.ID).GetTask(mustTaskID(t, a.task.ID))
				if err != nil || state.CategoryID == nil || *state.CategoryID != a.category {
					t.Fatalf("category not committed: %+v %v", state, err)
				}
				status(req(b, "DELETE", path, ""), 404)
				status(req(a, "DELETE", path, ""), 200)
			})
			t.Run("side_history_and_checkpoint_owner", func(t *testing.T) {
				parent := sidequestion.Parent{AccountID: a.account.ID, TaskID: mustTaskID(t, a.task.ID), ExplorationID: a.task.ExpID}
				snapshot := sidequestion.Snapshot{Parent: parent, RunID: 1, Version: 1, CapturedAt: time.Now().UTC()}
				pg := operator.ForAccount(a.account.ID)
				if err := pg.SaveSideSnapshot(t.Context(), snapshot); err != nil {
					t.Fatal(err)
				}
				exchange, _, err := pg.StartSideRequest(t.Context(), snapshot, "fixture-request-id", "own side question")
				if err != nil {
					t.Fatal(err)
				}
				s.side.mu.Lock()
				s.side.pending[parent.Key()] = snapshot
				s.side.mu.Unlock()
				s.flushSideSnapshots()
				w := req(a, "GET", "/tasks/"+a.task.ID+"/chat/side-questions", "")
				status(w, 200)
				if !strings.Contains(w.Body.String(), "own side question") {
					t.Fatal("side history missing")
				}
				status(req(b, "GET", "/tasks/"+a.task.ID+"/chat/side-questions", ""), 404)
				exchange.Answer = "saved without model"
				exchange.Status = "completed"
				exchange.Sequence++
				scoped, err := s.sideAccountDB(parent)
				if err != nil {
					t.Fatal(err)
				}
				if ok, err := scoped.UpdateSideRequest(t.Context(), *exchange); err != nil || !ok {
					t.Fatalf("side update %v %v", ok, err)
				}
			})
			t.Run("mcp_cache_and_failover_restart", func(t *testing.T) {
				pgA, pgB := m.pg.ForAccount(a.account.ID), m.pg.ForAccount(b.account.ID)
				if err := pgA.SaveMCPTools(a.mcp, []db.MCPTool{{Name: "owned-tool"}}); err != nil {
					t.Fatal(err)
				}
				if err := pgB.SaveMCPTools(a.mcp, []db.MCPTool{{Name: "foreign-tool"}}); err == nil {
					t.Fatal("foreign cache write accepted")
				}
				tools, err := pgA.MCPToolsDetailed(a.mcp)
				if err != nil || len(tools) != 1 || tools[0].Name != "owned-tool" {
					t.Fatalf("cache=%v err=%v", tools, err)
				}
				until := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
				if err := pgA.SaveLLMHealth(db.LLMHealth{ProfileID: a.profile, Trips: 1, OpenUntil: &until}); err != nil {
					t.Fatal(err)
				}
				if err := pgB.SaveLLMHealth(db.LLMHealth{ProfileID: a.profile, Trips: 9, OpenUntil: &until}); err == nil {
					t.Fatal("foreign breaker write accepted")
				}
				restored := newLLMHealthRegistry(m.pg)
				if !restored.Get(a.profile).OpenUntil.Equal(until) {
					t.Fatal("breaker deadline not restored")
				}
				restored.Reset(a.profile)
				rows, err := pgA.LoadLLMHealth()
				if err != nil || len(rows) != 0 {
					t.Fatalf("breaker reset not persisted %v %v", rows, err)
				}
			})
			t.Run("account_active_selection", func(t *testing.T) {
				m.SetActive(a.task.ID)
				m.SetActive(b.task.ID)
				if m.ActiveTaskForAccount(a.account.ID) != a.task || m.ActiveTaskForAccount(b.account.ID) != b.task {
					t.Fatal("selection crossed account")
				}
				r := withAccount(httptest.NewRequest("GET", "/api/stats", nil), a.account.ID)
				task, ok := s.taskForAccountOrActive(r, "active")
				if !ok || task.ID != a.task.ID {
					t.Fatal("HTTP lost account active task")
				}
			})
			if runtimeOnly {
				var count int
				if err := m.pg.QueryRow(`SELECT count(*) FROM findings`).Scan(&count); err != nil || count != 0 {
					t.Fatalf("root pool is not isolated: %d %v", count, err)
				}
			}
		})
	}
}

func TestFindingExportSkipsLongTenantTransaction(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"/api/exploration/findings/export", "/api/tasks/1/files/file-id", "/api/report"} {
		streamed := false
		h := s.withTenantTx(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := w.(*bufferedTenantResponse); ok {
				t.Fatal("download buffered")
			}
			_, streamed = w.(http.Flusher)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if !streamed {
			t.Fatalf("no streaming for %s", path)
		}
	}
}
