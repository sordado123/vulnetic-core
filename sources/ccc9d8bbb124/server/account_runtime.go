package server

import (
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/norma/transcript"
	"net/http"
	"path/filepath"
)

func (s *Server) accountTranscripts(accountID int64) *transcript.Store {
	legacy := filepath.Join(s.m.dir, "transcripts")
	if !config.SaaSMode() {
		return transcript.NewStore(legacy)
	}
	root := filepath.Join(s.m.dir, "accounts", fmt.Sprint(accountID))
	return transcript.NewAccountStore(filepath.Join(root, "transcripts"), root, legacy)
}

func (s *Server) skillDirForAccount(accountID int64) string {
	return filepath.Join(s.m.dir, "accounts", fmt.Sprint(accountID), "skills")
}
func (s *Server) requestSkillDir(w http.ResponseWriter, r *http.Request) (string, bool) {
	accountID, ok := requireAccountID(w, r)
	if !ok {
		return "", false
	}
	root, err := s.accountStorage(accountID)
	if err != nil {
		writeErr(w, 503, "Skill storage unavailable")
		return "", false
	}
	defer root.Close()
	if err := root.MkdirAll("skills", 0700); err != nil {
		writeErr(w, 503, "Skill storage unavailable")
		return "", false
	}
	skills, err := root.OpenRoot("skills")
	if err != nil {
		writeErr(w, 503, "Skill storage unavailable")
		return "", false
	}
	dir := skills.Name()
	skills.Close()
	return dir, true
}

func (s *Server) invalidateAccountAgents(accountID int64, removedProfiles ...int64) {
	profiles, err := s.m.pg.ListProfilesForAccount(accountID)
	if err != nil {
		return
	}
	ids := map[int64]bool{}
	for _, id := range removedProfiles {
		ids[id] = true
	}
	for _, profile := range profiles {
		ids[profile.ID] = true
	}
	s.profMu.Lock()
	for id := range ids {
		delete(s.profChatAgents, id)
	}
	s.profMu.Unlock()
	s.provCacheMu.Lock()
	s.provCacheGen++
	for id := range ids {
		delete(s.provByProfile, id)
	}
	s.provCacheMu.Unlock()
	tasks := map[string]bool{}
	for _, task := range s.m.List() {
		if task.AccountID == accountID {
			tasks[task.ID] = true
		}
	}
	for id := range tasks {
		s.evictTaskAgents(id)
	}
}
