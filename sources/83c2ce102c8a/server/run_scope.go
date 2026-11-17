package server

import (
	"context"
	"github.com/sordado123/vulnetic/db"
)

func (s *Server) taskForRun(ctx context.Context, id string) (*Task, bool) {
	task, ok := s.m.Task(id)
	if !ok || task.AccountID != toolRunAccountID(ctx, s.m.pg) {
		return nil, false
	}
	return task, true
}
func (s *Server) resolveTaskForRun(ctx context.Context, id string) *Task {
	if id == "" || id == "active" {
		active := s.m.ActiveTask()
		for _, task := range s.tasksForRun(ctx) {
			if active != nil && task.ID == active.ID {
				return task
			}
		}
		return nil
	}
	task, _ := s.taskForRun(ctx, id)
	return task
}
func (s *Server) tasksForRun(ctx context.Context) []*Task {
	account := toolRunAccountID(ctx, s.m.pg)
	out := []*Task{}
	for _, task := range s.m.List() {
		if task.AccountID == account && account > 0 {
			out = append(out, task)
		}
	}
	return out
}
func (s *Server) assetStoreForRun(ctx context.Context) *db.AssetStore {
	if store := s.assetStore(); store != nil {
		return store.ForAccount(toolRunAccountID(ctx, s.m.pg))
	}
	return nil
}
