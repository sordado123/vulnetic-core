package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestUsageDailyArchivedCalendarBounds(t *testing.T) {
	d := betaTestDB(t)
	name := fmt.Sprintf("usage-days-%d", time.Now().UnixNano())
	a, _, err := d.CreateAccountWithAdmin(name, name+"@fixture.invalid", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM users WHERE account_id=$1`, a.ID)
		_, _ = d.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID)
	})
	pg := d.ForAccount(a.ID)
	task, err := pg.CreateTaskWithOptions("Archived usage", "fixture", TaskCreateOptions{AccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	rows := []ProfileDayUsage{}
	for _, age := range []int{0, 6, 7, 29, 30, 89, 90, 179, 180, 364, 365, -1} {
		rows = append(rows, ProfileDayUsage{ProfileName: "Archived profile", Date: today.AddDate(0, 0, -age).Format("2006-01-02"), InputTokens: age + 2, OutputTokens: 1})
	}
	aggregate, _ := json.Marshal(taskArchiveAggregate{TokenDaily: rows})
	if _, err := d.Exec(`INSERT INTO task_archives(task_id,state,aggregate_stats) VALUES ($1,'ready',$2)`, task.ID, aggregate); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{7, 30, 90, 180, 365} {
		got, err := pg.UsageDaily(days)
		if err != nil {
			t.Fatal(err)
		}
		want, total := 0, 0
		for _, row := range rows {
			if row.Date >= today.AddDate(0, 0, 1-days).Format("2006-01-02") && row.Date <= today.Format("2006-01-02") {
				want += row.InputTokens
			}
		}
		for _, row := range got {
			total += row.InputTokens
		}
		if total != want {
			t.Fatalf("archived %d days: got %d want %d", days, total, want)
		}
	}
}
