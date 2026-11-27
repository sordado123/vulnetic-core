package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func taskPage(list []TaskDTO, r *http.Request) ([]TaskDTO, int, int, map[string]int, error) {
	query := r.URL.Query()
	counts := map[string]int{}
	for _, t := range list {
		counts[t.Status]++
	}
	accountTotal := len(list)
	if query.Get("page") == "" && query.Get("summary") != "true" {
		return list, len(list), accountTotal, counts, nil
	}
	status, q, category := query.Get("status"), strings.ToLower(strings.TrimSpace(query.Get("q"))), query.Get("category")
	filtered := make([]TaskDTO, 0, len(list))
	for _, t := range list {
		if status != "" && status != "all" && t.Status != status {
			continue
		}
		if category == "uncategorized" && t.CategoryID != nil {
			continue
		}
		if category != "" && category != "all" && category != "uncategorized" && (t.CategoryID == nil || strconv.FormatInt(*t.CategoryID, 10) != category) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(t.ID+" "+t.Name+" "+t.CategoryName+" "+t.Description+" "+t.Goal), q) {
			continue
		}
		filtered = append(filtered, t)
	}
	field, asc := query.Get("sort"), query.Get("direction") == "asc"
	if query.Get("summary") == "true" {
		field = "activity"
		asc = false
	}
	rank := map[string]int{"created": 0, "queued": 1, "running": 2, "paused": 3, "done": 4, "failed": 5, "timeout": 6}
	now := time.Now().Unix()
	duration := func(t TaskDTO) int64 {
		end := t.LastActivity
		if t.Status == "running" {
			end = now
		} else if t.CompletedUnix > 0 {
			end = t.CompletedUnix
		}
		return max(0, end-t.CreatedUnix)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		if field != "activity" {
			if a.Pinned != b.Pinned {
				return a.Pinned
			}
			if a.Pinned && a.PinnedAt != b.PinnedAt {
				return a.PinnedAt > b.PinnedAt
			}
		}
		var x, y int64
		switch field {
		case "created":
			x, y = a.CreatedUnix, b.CreatedUnix
		case "duration":
			x, y = duration(a), duration(b)
		case "status":
			x, y = int64(rank[a.Status]), int64(rank[b.Status])
		case "activity":
			x, y = max(a.LastActivity, a.CreatedUnix), max(b.LastActivity, b.CreatedUnix)
		default:
			x, _ = strconv.ParseInt(a.ID, 10, 64)
			y, _ = strconv.ParseInt(b.ID, 10, 64)
		}
		if x == y {
			ai, _ := strconv.ParseInt(a.ID, 10, 64)
			bi, _ := strconv.ParseInt(b.ID, 10, 64)
			return ai > bi
		}
		if asc {
			return x < y
		}
		return x > y
	})
	total := len(filtered)
	page := max(1, atoiDefault(query.Get("page"), 1))
	size := min(100, max(1, atoiDefault(query.Get("size"), 20)))
	if query.Get("summary") == "true" {
		page = 1
		size = 5
	}
	start := total
	if page <= total/size+1 {
		start = min(total, (page-1)*size)
	}
	return filtered[start:min(total, start+size)], total, accountTotal, counts, nil
}
