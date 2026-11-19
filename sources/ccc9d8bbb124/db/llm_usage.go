package db

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"sort"
	"strconv"
	"time"
)

// LLMUsage is one lightweight LLM-call metering row — the always-on usage ledger,
// distinct from llm_records (which stores full request/response bodies and is a
// gated debug feature). One row per completion call, written on both success and
// error, so token accounting is complete even for interrupted/failed runs. Carries
// only the dimensions needed to slice token spend (model / profile / task / agent),
// never any prompt or response content.
type LLMUsage struct {
	ConversationID int64     `json:"conversation_id,omitempty"`
	RunID          string    `json:"run_id,omitempty"`
	CallID         string    `json:"call_id,omitempty"`
	RecordedAt     time.Time `json:"recorded_at,omitempty"`
	AccountID      int64     `json:"-"`
	TaskID         string    `json:"task_id"`        // task registry id (matches llm_records.task_id)
	ExplorationID  int64     `json:"exploration_id"` // exploration id parsed from the session (0 = unknown/non-task)
	Worker         string    `json:"worker"`         // agent lane: worker / planner / mainagent / goals
	Model          string    `json:"model"`
	ProfileName    string    `json:"profile_name"`
	LatencyMs      int       `json:"latency_ms"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	CacheRead      int       `json:"cache_read"`
	CacheWrite     int       `json:"cache_write"`
	Status         string    `json:"status"` // ok | error
}

const llmUsageSchema = `
CREATE TABLE IF NOT EXISTS llm_usage (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    task_id        TEXT,
    exploration_id BIGINT,
    worker         TEXT,
    model          TEXT,
    profile_name   TEXT,
    latency_ms     INTEGER,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_read     INTEGER NOT NULL DEFAULT 0,
    cache_write    INTEGER NOT NULL DEFAULT 0,
    status         TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_task  ON llm_usage(task_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_model ON llm_usage(task_id, model);
CREATE INDEX IF NOT EXISTS idx_llm_usage_exp   ON llm_usage(exploration_id);
`

// EnsureLLMUsageTable creates the llm_usage metering table if it does not exist.
func (d *DB) EnsureLLMUsageTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(llmUsageSchema); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertLLMUsage appends one metering row. Best-effort: callers log and continue on
// error; a configured durable journal retains failed inserts for replay.
func (d *DB) InsertLLMUsage(u *LLMUsage) error {
	if d.RuntimeOnly() && !d.hasAccount {
		owner, ok := d.ledgerAccount(u.AccountID, u.TaskID, "").(int64)
		if !ok || owner <= 0 {
			return errors.New("execution attribution is required")
		}
		d = d.ForAccount(owner)
	}
	if u.RunID != "" || u.ConversationID > 0 {
		var owned bool
		err := d.QueryRow(`SELECT ($1='' OR EXISTS(SELECT 1 FROM execution_runs WHERE id=$1 AND account_id=$3)) AND ($2::bigint=0 OR EXISTS(SELECT 1 FROM conversations WHERE id=$2 AND account_id=$3) OR EXISTS(SELECT 1 FROM execution_runs WHERE id=$1 AND account_id=$3 AND (payload->>'conversation_id')::bigint=$2))`, u.RunID, u.ConversationID, d.ledgerAccount(u.AccountID, u.TaskID, "")).Scan(&owned)
		if err != nil {
			return err
		}
		if !owned {
			return errors.New("usage execution owner mismatch")
		}
	}
	if u.CallID == "" {
		u.CallID = uuid.NewString()
	}
	if u.RecordedAt.IsZero() {
		u.RecordedAt = time.Now().UTC()
	}
	owner, ok := d.ledgerAccount(u.AccountID, u.TaskID, "").(int64)
	if d.usageJournal != nil {
		if !ok || owner <= 0 {
			return errors.New("usage account is required")
		}
		u.AccountID = owner
		return d.journalUsage(u)
	}
	return d.insertLLMUsage(u)
}
func (d *DB) insertLLMUsage(u *LLMUsage) error {
	var expID any
	if u.ExplorationID > 0 {
		expID = u.ExplorationID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.ExecContext(ctx, `
INSERT INTO llm_usage(task_id, exploration_id, worker, model, profile_name, latency_ms, input_tokens, output_tokens, cache_read, cache_write, status,account_id,call_id,ts,conversation_id,run_id)
SELECT NULLIF($1,''),$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),$14,NULLIF($15,0),NULLIF($16,'') WHERE ($16='' OR EXISTS(SELECT 1 FROM execution_runs r WHERE r.id=$16 AND r.account_id=$12)) AND ($15::bigint=0 OR EXISTS(SELECT 1 FROM conversations c WHERE c.id=$15 AND c.account_id=$12) OR EXISTS(SELECT 1 FROM execution_runs r WHERE r.id=$16 AND r.account_id=$12 AND (r.payload->>'conversation_id')::bigint=$15)) ON CONFLICT(account_id,call_id) WHERE call_id IS NOT NULL DO NOTHING`,
		u.TaskID, expID, u.Worker, u.Model, u.ProfileName,
		u.LatencyMs, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.Status, d.ledgerAccount(u.AccountID, u.TaskID, ""), u.CallID, u.RecordedAt, u.ConversationID, u.RunID)
	return err
}

// TokenByModel aggregates a task's LLM token usage grouped by model, most-used
// first, from the always-on llm_usage ledger. taskID is the task registry id.
// Accurate even with per-agent model bindings, pool rotation/failover, and
// interrupted runs, since every call (success or error) is metered.
func (d *DB) TokenByModel(taskID string) ([]ModelTokenStat, error) {
	rows, err := d.Query(`
SELECT COALESCE(NULLIF(model,''),'(unknown)') AS model, COUNT(*) AS calls,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE `+d.tenantSQL("")+` AND COALESCE(task_id,'') = $1
GROUP BY model
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC, model`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ModelTokenStat{}
	for rows.Next() {
		var m ModelTokenStat
		if err := rows.Scan(&m.Model, &m.Calls, &m.InputTokens, &m.OutputTokens,
			&m.CacheReadTokens, &m.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ProfileUsage aggregates the whole ledger's token spend for one LLM profile
// (global, all tasks). Powers the dashboard's per-profile token card (new source).
type ProfileUsage struct {
	ProfileName      string `json:"profile_name"`
	Calls            int    `json:"calls"`
	Tasks            int    `json:"tasks"`
	InputTokens      int    `json:"input_tokens"`
	OutputTokens     int    `json:"output_tokens"`
	CacheReadTokens  int    `json:"cache_read_tokens"`
	CacheWriteTokens int    `json:"cache_write_tokens"`
	// CostEur is set only when the profile carries at least one price; nil = not priced.
	CostEur *float64 `json:"cost_eur,omitempty"`
}

// UsageByProfile returns global token spend grouped by profile name, most-used
// first. profile_name may be empty for calls made on env/non-persisted configs.
func (d *DB) UsageByProfile() ([]ProfileUsage, error) {
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name, COUNT(*) AS calls,
       COUNT(DISTINCT task_id) AS tasks,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage WHERE ` + d.tenantSQL("") + `
GROUP BY profile_name
ORDER BY SUM(input_tokens) + SUM(output_tokens) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileUsage{}
	for rows.Next() {
		var p ProfileUsage
		if err := rows.Scan(&p.ProfileName, &p.Calls, &p.Tasks,
			&p.InputTokens, &p.OutputTokens, &p.CacheReadTokens, &p.CacheWriteTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]ProfileUsage, len(out))
	for _, current := range out {
		byName[current.ProfileName] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenProfiles {
			current := byName[cold.ProfileName]
			current.ProfileName = cold.ProfileName
			current.Calls += cold.Calls
			current.Tasks += cold.Tasks
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			current.CacheWriteTokens += cold.CacheWriteTokens
			byName[cold.ProfileName] = current
		}
	}
	out = out[:0]
	for _, current := range byName {
		out = append(out, current)
	}
	if err := applyCostEur(d, out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].InputTokens + out[i].OutputTokens
		right := out[j].InputTokens + out[j].OutputTokens
		if left != right {
			return left > right
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// ProfileDayUsage is one (profile, UTC calendar day) token bucket for the daily
// chart. Unlike the activity-based chart, ts is the real call time, so this is
// actual per-day consumption rather than tokens bucketed by task creation date.
type ProfileDayUsage struct {
	ProfileName     string `json:"profile_name"`
	Date            string `json:"date"` // YYYY-MM-DD (UTC)
	InputTokens     int    `json:"input_tokens"`
	OutputTokens    int    `json:"output_tokens"`
	CacheReadTokens int    `json:"cache_read_tokens"`
}

// UsageDaily returns per-(profile, day) token buckets for the past `days` days
// (default 365 when days<=0), so the dashboard can slice by profile + range.
func (d *DB) UsageDaily(days int) ([]ProfileDayUsage, error) {
	if days <= 0 {
		days = 365
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	start, end := today.AddDate(0, 0, 1-days), today.AddDate(0, 0, 1)
	rows, err := d.Query(`
SELECT COALESCE(profile_name,'') AS profile_name,
       to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0)
FROM llm_usage
WHERE `+d.tenantSQL("")+` AND ts >= $1 AND ts < $2
GROUP BY profile_name, day
ORDER BY day`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProfileDayUsage{}
	for rows.Next() {
		var p ProfileDayUsage
		if err := rows.Scan(&p.ProfileName, &p.Date, &p.InputTokens, &p.OutputTokens, &p.CacheReadTokens); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	cutoff, until := start.Format("2006-01-02"), end.Format("2006-01-02")
	byKey := make(map[string]ProfileDayUsage, len(out))
	for _, current := range out {
		byKey[current.ProfileName+"\x00"+current.Date] = current
	}
	for _, aggregate := range archived {
		for _, cold := range aggregate.TokenDaily {
			if cold.Date < cutoff || cold.Date >= until {
				continue
			}
			key := cold.ProfileName + "\x00" + cold.Date
			current := byKey[key]
			current.ProfileName = cold.ProfileName
			current.Date = cold.Date
			current.InputTokens += cold.InputTokens
			current.OutputTokens += cold.OutputTokens
			current.CacheReadTokens += cold.CacheReadTokens
			byKey[key] = current
		}
	}
	out = out[:0]
	for _, current := range byKey {
		out = append(out, current)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].ProfileName < out[j].ProfileName
	})
	return out, nil
}

// JudgeDayUsage is one UTC-day token bucket for the intercept fallback judge,
// for the config page's recent-spend sparkline.
type JudgeDayUsage struct {
	Date         string `json:"date"` // YYYY-MM-DD (UTC)
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
}

// JudgeUsage is the cumulative token spend of the intercept fallback judge
// (worker='judge' rows in the always-on ledger), plus a recent daily series.
type JudgeUsage struct {
	Calls            int             `json:"calls"`
	InputTokens      int             `json:"input_tokens"`
	OutputTokens     int             `json:"output_tokens"`
	CacheReadTokens  int             `json:"cache_read_tokens"`
	CacheWriteTokens int             `json:"cache_write_tokens"`
	Daily            []JudgeDayUsage `json:"daily"`
}

// JudgeUsageStats returns the fallback judge's all-time token totals and a
// per-day series over the past `days` days (default 30). Sourced from the
// always-on llm_usage ledger, so it is accurate across pool rotation and
// interrupted/failed judge calls. days only bounds the daily series; totals are
// all-time.
func (d *DB) JudgeUsageStats(days int) (JudgeUsage, error) {
	if days <= 0 {
		days = 30
	}
	var u JudgeUsage
	err := d.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
       COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage
WHERE `+d.tenantSQL("")+` AND worker = 'judge'`).Scan(&u.Calls, &u.InputTokens, &u.OutputTokens,
		&u.CacheReadTokens, &u.CacheWriteTokens)
	if err != nil {
		return JudgeUsage{}, err
	}
	rows, err := d.Query(`
SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
       COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
FROM llm_usage
WHERE `+d.tenantSQL("")+` AND worker = 'judge' AND ts >= now() - ($1 * interval '1 day')
GROUP BY day
ORDER BY day`, days)
	if err != nil {
		return JudgeUsage{}, err
	}
	defer rows.Close()
	u.Daily = []JudgeDayUsage{}
	for rows.Next() {
		var day JudgeDayUsage
		if err := rows.Scan(&day.Date, &day.Calls, &day.InputTokens, &day.OutputTokens); err != nil {
			return JudgeUsage{}, err
		}
		u.Daily = append(u.Daily, day)
	}
	if err := rows.Err(); err != nil {
		return JudgeUsage{}, err
	}
	return u, nil
}

// ParseExpID turns the exploration-id segment parsed from a session string into an
// int64 (0 when empty/non-numeric, e.g. chat sessions keyed by conversation id).
func ParseExpID(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// applyCostEur fills CostEur on each profile bucket from the stored per-profile
// prices (EUR per 1M tokens). Profiles without any price keep CostEur nil. The
// join is by profile name (llm_usage records the name, not the id); the first
// matching profile wins, and duplicate names are a configuration error the
// operator sees as a weird number, not a crash.
// profilePrice is one profile's per-1M-token prices (EUR).
type profilePrice struct{ in, outp, cr, cw float64 }

func (p profilePrice) zero() bool { return p.in == 0 && p.outp == 0 && p.cr == 0 && p.cw == 0 }

// costEur charges a token bucket at this profile's prices. InputTokens includes
// the cached subset (Anthropic/OpenAI usage semantics), so the fresh share is
// input minus cache reads (clamped ≥0) to avoid double-charging the cache.
func (p profilePrice) costEur(input, output, cacheRead, cacheWrite int) float64 {
	fresh := input - cacheRead
	if fresh < 0 {
		fresh = 0
	}
	return float64(fresh)/1e6*p.in + float64(output)/1e6*p.outp +
		float64(cacheRead)/1e6*p.cr + float64(cacheWrite)/1e6*p.cw
}

// profilePrices loads each profile's prices keyed by name. The first profile of a
// duplicated name wins (a config error the operator sees as a weird number, not a
// crash). Account-scoped via tenantSQL.
func (d *DB) profilePrices() (map[string]profilePrice, error) {
	rows, err := d.Query(`SELECT name, COALESCE(price_input_per_m,0), COALESCE(price_output_per_m,0), COALESCE(price_cache_read_per_m,0), COALESCE(price_cache_write_per_m,0) FROM llm_profiles WHERE ` + d.tenantSQL(""))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byName := map[string]profilePrice{}
	for rows.Next() {
		var n string
		var pr profilePrice
		if err := rows.Scan(&n, &pr.in, &pr.outp, &pr.cr, &pr.cw); err != nil {
			return nil, err
		}
		if _, seen := byName[n]; !seen {
			byName[n] = pr
		}
	}
	return byName, rows.Err()
}

func applyCostEur(d *DB, out []ProfileUsage) error {
	byName, err := d.profilePrices()
	if err != nil {
		return err
	}
	for i := range out {
		pr, ok := byName[out[i].ProfileName]
		if !ok || pr.zero() {
			continue
		}
		c := pr.costEur(out[i].InputTokens, out[i].OutputTokens, out[i].CacheReadTokens, out[i].CacheWriteTokens)
		out[i].CostEur = &c
	}
	return nil
}

// TaskCostEur is a task's total LLM cost in EUR, applying each profile's prices to
// the task's metered usage (grouped by profile, since prices are per profile). It
// returns nil if any metered profile is unpriced, avoiding a misleading partial
// total. Account-scoped via tenantSQL.
func (d *DB) TaskCostEur(taskID string) (*float64, error) {
	if taskID == "" {
		return nil, nil
	}
	byName, err := d.profilePrices()
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT COALESCE(profile_name,''), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_write),0)
FROM llm_usage WHERE `+d.tenantSQL("")+` AND COALESCE(task_id,'') = $1 GROUP BY profile_name`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var total float64
	priced := false
	for rows.Next() {
		var name string
		var in, outp, cr, cw int
		if err := rows.Scan(&name, &in, &outp, &cr, &cw); err != nil {
			return nil, err
		}
		pr, ok := byName[name]
		if !ok || pr.zero() {
			if in+outp+cr+cw > 0 {
				return nil, nil
			}
			continue
		}
		total += pr.costEur(in, outp, cr, cw)
		priced = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !priced {
		return nil, nil
	}
	return &total, nil
}
