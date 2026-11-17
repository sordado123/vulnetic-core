package server

import (
	"log"
	"time"

	"github.com/sordado123/vulnetic/agent"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/norma/llm"
	"github.com/sordado123/vulnetic/llmpool"
)

// Server-side wiring for LLM pooling (failover). Design: docs/llm-polling-design.md:
//   - Only the global active-profile path pools (agent unbound, task not pinned);
//   - Bound/pinned paths own that profile exclusively by default: a failure is a failure (llm_pool_bind_fallback can turn on the fallback);
//   - Chain order = active profile → the rest by priority DESC, excluding pool_exclude ones;
//   - Circuit-breaker state is process-wide (s.llmHealth); rebuilding the pool does not clear it.

// newLLMHealthRegistry builds the process-wide circuit-breaker registry, mirroring
// state into PG so a cooling-off window survives a restart. Persistence errors
// are logged; the in-memory copy remains authoritative.
func newLLMHealthRegistry(pg *db.DB) *llmpool.Registry {
	if pg == nil {
		return llmpool.NewRegistry(nil, nil)
	}
	persist := func(id int64, st llmpool.State) {
		h := db.LLMHealth{ProfileID: id, Fails: st.Fails, Trips: st.Trips, LastError: st.LastError}
		if !st.OpenUntil.IsZero() {
			t := st.OpenUntil
			h.OpenUntil = &t
		}
		if err := pg.SaveLLMHealth(h); err != nil {
			log.Printf("[llmpool] failed to persist circuit-breaker state: %v", err)
		}
	}
	forget := func(id int64) {
		if err := pg.ClearLLMHealth(id); err != nil {
			log.Printf("[llmpool] clear circuit-breaker state: %v", err)
		}
	}
	reg := llmpool.NewRegistry(persist, forget)
	// Restore only windows that haven't expired (LoadLLMHealth filters), so a
	// profile that finished cooling while we were down comes back healthy.
	if rows, err := pg.LoadLLMHealth(); err == nil {
		for _, h := range rows {
			st := llmpool.State{Fails: h.Fails, Trips: h.Trips, LastError: h.LastError, LastAt: h.LastAt}
			if h.OpenUntil != nil {
				st.OpenUntil = *h.OpenUntil
			}
			reg.Restore(h.ProfileID, st)
			log.Printf("[llmpool] restored circuit-breaker state: profile #%d cooling until %s", h.ProfileID, st.OpenUntil.Format(time.RFC3339))
		}
	} else {
		log.Printf("[llmpool] restore circuit-breaker state: %v", err)
	}
	return reg
}

// poolMember builds one chain member from a profile, reusing the per-profile
// provider cache so every agent pointing at the same profile shares one provider
// (hence one rate limiter). Returns nil when the profile can't be built.
func (s *Server) poolMember(p *db.LLMProfile, rank int) *llmpool.Member {
	prov, cfg, ok := s.providerForProfile(p.ID)
	if !ok {
		return nil
	}
	return &llmpool.Member{
		ID: p.ID, Name: p.Name, Model: p.Model, Format: p.Format,
		Priority: p.Priority, Active: p.IsDefault, Rank: rank,
		WindowTokens: cfg.CompactionWindow(), Prov: prov,
	}
}

// poolChain reads the failover chain from the DB. headID/headProv/headCfg describe
// the member that must lead the chain — the globally active profile on the normal
// path, or an explicitly bound one when bound-profile fallback is on. The head is
// passed in (rather than resolved through the cache) so applyLLM's already-built
// provider is reused instead of duplicated.
//
// Returns nil when failover is off or the chain has fewer than two usable members
// — callers then use the bare provider, which is byte-for-byte the old behavior.
func (s *Server) poolChain(headID int64, headProv llm.Provider, headCfg agent.Config) *llmpool.Pool {
	if s.m == nil || s.m.pg == nil || (!config.SaaSMode() && !s.m.LLMPoolEnabled()) {
		return nil
	}
	owner, err := s.m.pg.ProfileAccountID(headID)
	if err != nil || owner <= 0 {
		return nil
	}
	pg := s.m.pg.ForAccount(owner)
	s.applyAccountHealthPolicy(owner)
	if config.SaaSMode() && !pg.GetBool(settingLLMPoolOn, false) {
		return nil
	}
	profs, err := pg.PoolProfiles()
	if err != nil {
		log.Printf("[llmpool] failed to read the pool chain: %v", err)
		return nil
	}
	var head *db.LLMProfile
	for _, p := range profs {
		if p.ID == headID {
			head = p
			break
		}
	}
	if head == nil { // head excluded from the chain (bound + pool_exclude) — still leads
		if p, err := pg.ProfileByID(headID); err == nil && p != nil {
			head = p
		} else {
			return nil
		}
	}
	members := []*llmpool.Member{{
		ID: head.ID, Name: head.Name, Model: head.Model, Format: head.Format,
		Priority: head.Priority, Active: head.IsDefault, Rank: llmpool.RankActive,
		WindowTokens: headCfg.CompactionWindow(), Prov: headProv,
	}}
	for _, p := range profs {
		if p.ID == headID {
			continue
		}
		// The globally active profile outranks the others when it isn't the head
		// (bound-fallback chains), so it stays the first fallback tried.
		rank := p.Priority
		if p.IsDefault {
			rank = llmpool.RankActive - 1
		}
		if m := s.poolMember(p, rank); m != nil {
			members = append(members, m)
		}
	}
	if len(members) < 2 {
		return nil // nothing to fail over to
	}
	return llmpool.New(members, s.llmHealth)
}

// poolForActive wraps the globally-active provider in the failover chain. Returns
// prov unchanged when failover is off or there's nothing to fall back to.
func (s *Server) poolForActive(activeID int64, prov llm.Provider, cfg agent.Config) llm.Provider {
	pool := s.poolChain(activeID, prov, cfg)
	if pool == nil {
		return prov
	}
	names := make([]string, 0, len(pool.Members()))
	for _, m := range pool.Members() {
		names = append(names, m.Name+"/"+m.Model)
	}
	log.Printf("[llmpool] LLM pooling enabled, chain (%d): %v", len(names), names)
	return pool
}

// poolForBinding wraps a BOUND profile's provider so it falls back to the chain.
// Only active when both the failover master switch and the bound-fallback switch
// are on; otherwise a bound profile stays exclusive (fails hard), which is the
// default and the documented precedence.
func (s *Server) poolForBinding(id int64, prov llm.Provider, cfg agent.Config) llm.Provider {
	if s.m == nil || s.m.pg == nil {
		return prov
	}
	owner, err := s.m.pg.ProfileAccountID(id)
	if err != nil {
		return prov
	}
	pg := s.m.pg.ForAccount(owner)
	enabled, bound := s.m.LLMPoolEnabled(), s.m.LLMPoolBindFallback()
	if config.SaaSMode() {
		enabled = pg.GetBool(settingLLMPoolOn, false)
		bound = pg.GetBool(settingLLMPoolBindFallback, false)
	}
	if !enabled || !bound {
		return prov
	}
	if pool := s.poolChain(id, prov, cfg); pool != nil {
		return pool
	}
	return prov
}

// LLMPoolMemberStatus is one chain entry as shown in the UI.
type LLMPoolMemberStatus struct {
	ProfileID string `json:"profile_id"`
	Name      string `json:"name"`
	Model     string `json:"model"`
	Format    string `json:"format"`
	Priority  int    `json:"priority"`
	Active    bool   `json:"active"`   // is the globally-activated profile
	Excluded  bool   `json:"excluded"` // pool_exclude — not a failover target
	// Health: state is "ok" | "degraded" (failing but not tripped) | "tripped".
	State        string `json:"state"`
	Fails        int    `json:"fails"`
	Trips        int    `json:"trips"`
	CooldownSecs int    `json:"cooldown_secs"` // remaining cooling-off seconds; 0 = none
	LastError    string `json:"last_error,omitempty"`
	LastAt       string `json:"last_at,omitempty"`
}

// llmPoolStatus reports the whole picture for the LLM page: whether failover is
// on, the resolved chain order, and each profile's breaker state. Excluded
// profiles are listed too (flagged), so the user can see why one isn't in line.
func (s *Server) llmPoolStatus(accountID int64) map[string]any {
	out := map[string]any{
		"enabled":       false,
		"bind_fallback": false,
		"chain":         []LLMPoolMemberStatus{},
	}
	if s.m == nil || s.m.pg == nil {
		return out
	}
	out["enabled"] = s.m.LLMPoolEnabled()
	if config.SaaSMode() {
		out["enabled"] = s.m.pg.ForAccount(accountID).GetBool(settingLLMPoolOn, false)
	}
	out["bind_fallback"] = s.m.LLMPoolBindFallback()
	if config.SaaSMode() {
		out["bind_fallback"] = s.m.pg.ForAccount(accountID).GetBool(settingLLMPoolBindFallback, false)
	}

	all, err := s.m.pg.ListProfilesForAccount(accountID)
	if err != nil {
		return out
	}
	health := s.llmHealth.Snapshot()
	now := time.Now()
	// Chain order: active first, then priority DESC / id ASC — the same ordering
	// PoolProfiles applies, recomputed here so excluded ones can be shown in place.
	chain := make([]LLMPoolMemberStatus, 0, len(all))
	for _, p := range all {
		st := health[p.ID]
		m := LLMPoolMemberStatus{
			ProfileID: i64s(p.ID), Name: p.Name, Model: p.Model, Format: p.Format,
			Priority: p.Priority, Active: p.IsDefault, Excluded: p.PoolExclude,
			State: "ok", Fails: st.Fails, Trips: st.Trips,
			LastError: st.LastError,
		}
		if st.Open() {
			m.State = "tripped"
			m.CooldownSecs = int(st.OpenUntil.Sub(now).Seconds()) + 1
		} else if st.Fails > 0 {
			m.State = "degraded"
		}
		if !st.LastAt.IsZero() {
			m.LastAt = st.LastAt.Format(time.RFC3339)
		}
		chain = append(chain, m)
	}
	sortPoolStatus(chain)
	out["chain"] = chain
	return out
}

// sortPoolStatus orders the status rows exactly like the live chain: active first,
// then priority DESC, then id ASC (the incoming slice is already id-ordered, so a
// stable insertion sort on the first two keys is enough).
func sortPoolStatus(in []LLMPoolMemberStatus) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && poolLess(in[j], in[j-1]); j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func poolLess(a, b LLMPoolMemberStatus) bool {
	if a.Active != b.Active {
		return a.Active
	}
	return a.Priority > b.Priority
}
