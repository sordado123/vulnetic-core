package server

import (
	"testing"
	"time"
)

func TestParseScheduleTime(t *testing.T) {
	now := time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		raw  string
		want time.Time
		err  bool
	}{
		{"HH:MM later today", "21:00", time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC), false},
		{"HH:MM already past rolls to tomorrow", "19:00", time.Date(2026, 10, 25, 19, 0, 0, 0, time.UTC), false},
		{"HH:MM equal to now rolls to tomorrow", "20:00", time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC), false},
		{"H:MM single digit hour", "9:05", time.Date(2026, 10, 25, 9, 5, 0, 0, time.UTC), false},
		{"21h shorthand", "21h", time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC), false},
		{"21h30 shorthand", "21h30", time.Date(2026, 10, 24, 21, 30, 0, 0, time.UTC), false},
		{"RFC3339 passthrough", "2026-12-01T10:00:00Z", time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC), false},
		{"garbage rejected", "not-a-time", time.Time{}, true},
		{"hour out of range rejected", "25:00", time.Time{}, true},
		{"minute out of range rejected", "10:99", time.Time{}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseScheduleTime(c.raw, now)
			if c.err {
				if err == nil {
					t.Fatalf("parseScheduleTime(%q): expected an error, got %v", c.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScheduleTime(%q): unexpected error: %v", c.raw, err)
			}
			if !got.Equal(c.want) {
				t.Fatalf("parseScheduleTime(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}
