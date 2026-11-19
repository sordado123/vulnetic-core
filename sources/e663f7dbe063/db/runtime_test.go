package db

import (
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"testing"
	"time"
)

func TestRuntimeRLSWithoutOwnerCredential(t *testing.T) {
	t.Setenv("VULNETIC_PG_APP_PASSWORD", rlsTestAppPassword)
	owner, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	dsn, err := config.PostgresAppDSN()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, query := range []string{`CREATE TABLE forbidden_runtime_table(id int)`, `ALTER ROLE vulnetic_app BYPASSRLS`, `SELECT pg_read_file('/etc/shadow')`} {
		if _, e := runtime.Exec(query); e == nil {
			t.Fatalf("runtime privilege allowed: %s", query)
		}
	}
	var accounts []Account
	for i := 0; i < 2; i++ {
		a, _, e := owner.CreateAccountWithAdmin(fmt.Sprintf("runtime-%d-%d", i, time.Now().UnixNano()), fmt.Sprintf("runtime-%d-%d@fixture.test", i, time.Now().UnixNano()), "fakehash")
		if e != nil {
			t.Fatal(e)
		}
		accounts = append(accounts, a)
		t.Cleanup(func() {
			_, _ = owner.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
			_, _ = owner.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
		})
	}
	var taskIDs []int64
	for i, a := range accounts {
		task, e := runtime.CreateTaskWithOptions("runtime fixture", "authorized private lab", TaskCreateOptions{AccountID: a.ID})
		if e != nil {
			t.Fatal("runtime task create", e)
		}
		taskIDs = append(taskIDs, task.ID)
		task, e = runtime.GetTask(task.ID)
		if e != nil || task == nil || task.AccountID != a.ID {
			t.Fatal("background owner resolution failed", e)
		}
		if e = runtime.ForAccount(a.ID).SetSetting("same-key", fmt.Sprint(i)); e != nil {
			t.Fatal(e)
		}
	}
	for i, a := range accounts {
		scoped := runtime.ForAccount(a.ID)
		var count int
		if err = scoped.QueryRow(`SELECT count(*) FROM tasks`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("unfiltered account query escaped RLS: %d %v", count, err)
		}
		other, e := scoped.GetTask(taskIDs[1-i])
		if e != nil || other != nil {
			t.Fatalf("foreign task visible: %v %v", other, e)
		}
		value, _, e := scoped.GetSetting("same-key")
		if e != nil || value != fmt.Sprint(i) {
			t.Fatal("account setting leaked", e)
		}
	}
	var count int
	if err = runtime.QueryRow(`SELECT count(*) FROM tasks`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unscoped runtime accessed tenant tasks", count, err)
	}
	if _, _, e := runtime.UserByEmail("not-a-login@fixture.test"); e != ErrUserNotFound {
		t.Fatal("restricted login lookup failed", e)
	}
	tasks, e := runtime.ListTasks()
	if e != nil || len(tasks) < 2 {
		t.Fatal("background queue enumeration failed", e)
	}
	if _, e := OpenRuntime(testDSN(t)); e == nil {
		t.Fatal("table owner accepted as runtime")
	}
}
