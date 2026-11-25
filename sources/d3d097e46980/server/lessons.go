package server

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
)

// rsiLessonsMode reads the shadow-mode switch (VULNETIC_RSI_LESSONS, deprecated
// alias ARTEX_RSI_LESSONS):
//
//	off (default)  no selection, no logging, no prompt change
//	shadow         select lessons and log what would have been shown
//	inject         select, log, and append the block to planner/worker prompts
//
// The flag is read per task-bundle build, so changing it needs a new task or a
// task-agent invalidation, not a restart.
func rsiLessonsMode() string {
	switch strings.ToLower(strings.TrimSpace(config.GetenvCompat("VULNETIC_RSI_LESSONS", "ARTEX_RSI_LESSONS"))) {
	case "shadow":
		return "shadow"
	case "inject":
		return "inject"
	default:
		return "off"
	}
}

// wireTaskLessons selects the lessons visible to a task and, in inject mode,
// attaches the rendered block to the planner and worker. The block is
// code-owned: it is appended after the rendered prompt and cannot be removed
// by editing the prompt in the UI. Usage is logged in both modes so a later
// comparison can tell which tasks saw which lessons.
func (s *Server) wireTaskLessons(t *Task, wk *agent.Worker, pl *agent.Planner) {
	mode := rsiLessonsMode()
	if mode == "off" || t == nil {
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return
	}
	lessons, err := s.m.PG().TaskLessons(context.Background(), taskID, 8)
	if err != nil {
		log.Printf("[rsi] lesson selection failed for task %s: %v", t.ID, err)
		return
	}
	block := db.RenderLessons(lessons, 1800)
	if block == "" {
		return
	}
	if mode == "inject" {
		wk.SetLessonsBlock(block)
		pl.SetLessonsBlock(block)
	}
	ids := make([]int64, 0, len(lessons))
	for _, l := range lessons {
		ids = append(ids, l.ID)
	}
	if err := s.m.PG().LogLessonUsage(context.Background(), taskID, ids, mode); err != nil {
		log.Printf("[rsi] lesson usage log failed for task %s: %v", t.ID, err)
	}
}

// taskLessons returns the lessons visible to one task plus the rendered block.
// Read-only: it never extracts.
func (s *Server) taskLessons(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 500, "task id is not numeric")
		return
	}
	lessons, err := s.m.pg.ForAccount(mustRequestAccount(r)).TaskLessons(r.Context(), id, 50)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "task not found")
		return
	}
	if err != nil {
		log.Printf("[rsi] lesson list failed for task %d: %v", id, err)
		writeErr(w, 500, "lesson query failed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"mode":    rsiLessonsMode(),
		"lessons": lessons,
		"block":   db.RenderLessons(lessons, 1800),
		"count":   len(lessons),
	})
}

// accountLessons returns what the agent has learned about this account's own
// environment (#11), scoped to the account's companies (never cross-account
// category-only lessons). Read-only. Account-scoped via mustRequestAccount.
func (s *Server) accountLessons(w http.ResponseWriter, r *http.Request) {
	accountID := mustRequestAccount(r)
	lessons, err := s.m.pg.ForAccount(accountID).AccountLessons(r.Context(), accountID, 50)
	if err != nil {
		log.Printf("[rsi] account lessons failed for %d: %v", accountID, err)
		writeErr(w, 500, "lesson query failed")
		return
	}
	writeJSON(w, 200, map[string]any{"lessons": lessons, "count": len(lessons)})
}

// extractTaskLessons derives candidate lessons from one task's findings and
// retests. It is idempotent; call it after the task closes (the manager does
// this automatically on terminal status) or manually for a backfill.
func (s *Server) extractTaskLessons(w http.ResponseWriter, r *http.Request) {
	t, ok := s.taskForAccount(r, r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 500, "task id is not numeric")
		return
	}
	n, err := s.m.pg.ForAccount(mustRequestAccount(r)).ExtractLessonsForTask(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "task not found")
		return
	}
	if err != nil {
		log.Printf("[rsi] lesson extraction failed for task %d: %v", id, err)
		writeErr(w, 500, "lesson extraction failed")
		return
	}
	writeJSON(w, 200, map[string]any{"extracted": n})
}
