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
	"testing"
	"time"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
)

func TestDashboardUsageAccountAndCalendarDays(t *testing.T) {
	for _, runtimeOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime_%t", runtimeOnly), func(t *testing.T) {
			dsn, _, err := db.DSN()
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			u.Path = fmt.Sprintf("/vulnetic_dashboard_fixture_%d", time.Now().UnixNano())
			t.Setenv("VULNETIC_PG_DSN", u.String())
			t.Setenv("VULNETIC_SAAS_MODE", "false")
			appPassword := ""
			if runtimeOnly {
				appPassword = "dashboard-integration-fixture-only"
			}
			t.Setenv("VULNETIC_PG_APP_PASSWORD", appPassword)
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
			t.Cleanup(cancel)
			state := t.TempDir()
			s := New(ctx, m, state, state, state)
			host := httptest.NewServer(s.Handler())
			t.Cleanup(host.Close)
			create := func(name string) (db.Account, string, *Task) {
				t.Helper()
				a, user, err := m.pg.CreateAccountWithAdmin(name, name+"@fixture.invalid", "fixture", s.seedAccountCatalog)
				if err != nil {
					t.Fatal(err)
				}
				token, err := signJWTForPassword(s.jwtKey, a.ID, user.ID, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				task, err := m.CreateTaskWithOptions("Usage fixture", "No model calls", db.TaskCreateOptions{AccountID: a.ID, UserID: user.ID})
				if err != nil {
					t.Fatal(err)
				}
				return a, token, task
			}
			a, token, task := create("usage-a")
			b, foreign, other := create("usage-b")
			today := time.Now().UTC().Truncate(24 * time.Hour)
			ages := []int{0, 6, 7, 29, 30, 89, 90, 179, 180, 364, 365, -1}
			for _, age := range ages {
				value := age + 2
				if _, err := operator.Exec(`INSERT INTO llm_usage(account_id,task_id,profile_name,ts,input_tokens,output_tokens,cache_read,status) VALUES ($1,$2,'Same name',$3,$4,1,$5,'ok')`, a.ID, task.ID, today.AddDate(0, 0, -age), value, value/2); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := operator.Exec(`INSERT INTO llm_usage(account_id,task_id,profile_name,ts,input_tokens,output_tokens) VALUES ($1,$2,'Same name',$3,999999,999999)`, b.ID, other.ID, today); err != nil {
				t.Fatal(err)
			}
			for _, own := range []struct {
				task  *Task
				input int
			}{{task, 123}, {other, 999999}} {
				if _, err := operator.Exec(`INSERT INTO activity(exploration_id,kind,input_tokens,output_tokens) VALUES ($1,'result',$2,7)`, own.task.ExpID, own.input); err != nil {
					t.Fatal(err)
				}
			}
			conv, err := m.pg.ForAccount(a.ID).CreateConversation(a.ID, "auto", "Usage fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			input, output := 77, 3
			if _, err := m.pg.ForAccount(a.ID).AppendConvActivity(conv.ID, db.Activity{Kind: "result", InputTokens: &input, OutputTokens: &output}); err != nil {
				t.Fatal(err)
			}
			request := func(path, auth string, want int) []byte {
				t.Helper()
				req, _ := http.NewRequest("GET", host.URL+path, nil)
				if auth != "" {
					req.Header.Set("Authorization", "Bearer "+auth)
				}
				response, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				var body json.RawMessage
				if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != want {
					t.Fatalf("%s: got %d want %d: %s", path, response.StatusCode, want, body)
				}
				return body
			}
			for _, days := range []int{7, 30, 90, 180, 365} {
				var result struct {
					Daily []db.ProfileDayUsage `json:"daily"`
				}
				if err := json.Unmarshal(request("/api/tokens/usage?days="+strconv.Itoa(days), token, 200), &result); err != nil {
					t.Fatal(err)
				}
				want, got := 0, 0
				for _, age := range ages {
					if age >= 0 && age < days {
						want += age + 2
					}
				}
				for _, row := range result.Daily {
					if row.Date < today.AddDate(0, 0, 1-days).Format("2006-01-02") || row.Date > today.Format("2006-01-02") {
						t.Fatal("calendar boundary leaked", row)
					}
					got += row.InputTokens
				}
				if got != want {
					t.Fatalf("%d days: got %d want %d", days, got, want)
				}
			}
			var foreignUsage struct {
				Daily []db.ProfileDayUsage `json:"daily"`
			}
			if err := json.Unmarshal(request("/api/tokens/usage?days=7", foreign, 200), &foreignUsage); err != nil || len(foreignUsage.Daily) != 1 || foreignUsage.Daily[0].InputTokens != 999999 {
				t.Fatal("foreign usage mixed", err)
			}
			for _, path := range []string{"/api/tasks", "/api/tasks/" + task.ID} {
				raw := request(path, token, 200)
				var detail TaskDTO
				if path == "/api/tasks" {
					var list struct {
						Tasks []TaskDTO `json:"tasks"`
					}
					if json.Unmarshal(raw, &list) != nil || len(list.Tasks) != 1 {
						t.Fatal("task list is not isolated")
					}
					detail = list.Tasks[0]
				} else if err := json.Unmarshal(raw, &detail); err != nil {
					t.Fatal(err)
				}
				if detail.Tokens.InputTokens != 123 {
					t.Fatalf("task metrics missing account: %+v", detail.Tokens)
				}
			}
			var daily []db.DailyTokenBucket
			if err := json.Unmarshal(request("/api/tokens/daily?days=7", token, 200), &daily); err != nil || len(daily) != 1 || daily[0].InputTokens != 123 {
				t.Fatal("legacy daily not scoped", err)
			}
			var conversations []db.ConvTokenSummary
			if err := json.Unmarshal(request("/api/tokens/conversations", token, 200), &conversations); err != nil || len(conversations) != 1 || conversations[0].InputTokens != 77 {
				t.Fatal("conversation usage missing account", err)
			}
			request("/api/tokens/usage?days=0", token, 400)
			request("/api/tokens/usage?days=366", token, 400)
			request("/api/tokens/usage?days=invalid", token, 400)
			request("/api/tokens/usage?days=7", "", 401)
		})
	}
}
