package db

import (
	"database/sql"
	"github.com/sordado123/vulnetic/internal/evidenceredact"
	"strings"
	"time"
)

// ConvTokenSummary is one conversation's token total (sum of its kind='result'
// rows) with its profile + created_at, used to merge conversation usage into the
// dashboard's per-profile / daily token stats (which otherwise cover only tasks).
type ConvTokenSummary struct {
	LLMProfileID     *int64 `json:"llm_profile_id"`
	CreatedAt        string `json:"created_at"`
	InputTokens      int    `json:"input_tokens"`
	OutputTokens     int    `json:"output_tokens"`
	CacheReadTokens  int    `json:"cache_read_tokens"`
	CacheWriteTokens int    `json:"cache_write_tokens"`
}

// ConversationTokenSummaries returns one row per conversation with its summed
// result-row token usage (0 for conversations with no completed run yet).
func (d *DB) ConversationTokenSummaries() ([]ConvTokenSummary, error) {
	rows, err := d.Query(`
SELECT c.llm_profile_id, c.created_at::text,
       COALESCE(sum(ca.input_tokens),0), COALESCE(sum(ca.output_tokens),0),
       COALESCE(sum(ca.cache_read_tokens),0), COALESCE(sum(ca.cache_write_tokens),0)
FROM conversations c
LEFT JOIN conversation_activities ca ON ca.conversation_id = c.id AND ca.kind = 'result'
WHERE ` + d.tenantSQL("c.") + ` GROUP BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConvTokenSummary{}
	for rows.Next() {
		var s ConvTokenSummary
		var pid sql.NullInt64
		if err := rows.Scan(&pid, &s.CreatedAt, &s.InputTokens, &s.OutputTokens, &s.CacheReadTokens, &s.CacheWriteTokens); err != nil {
			return nil, err
		}
		if pid.Valid {
			v := pid.Int64
			s.LLMProfileID = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Conversation is one ChatGPT-style chat thread bound to an agent key. It lives
// independent of the pentest exploration graph — see schema.sql §I.
type Conversation struct {
	UserID       int64      `json:"-"`
	ID           int64      `json:"id"`
	AccountID    int64      `json:"-"` // owning account; never serialized to the API directly
	AgentKey     string     `json:"agent_key"`
	Title        string     `json:"title"`
	LLMProfileID *int64     `json:"llm_profile_id,omitempty"`
	SourceTaskID *int64     `json:"source_task_id,omitempty"`
	SSHTargetID  *int64     `json:"ssh_target_id,omitempty"`
	Pinned       bool       `json:"pinned"`
	PinnedAt     *time.Time `json:"pinned_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ConversationPatch updates only the fields whose pointers are non-nil.
type ConversationPatch struct {
	Title  *string
	Pinned *bool
}

const convCols = `id, account_id, agent_key, title, llm_profile_id, pinned_at, created_at, updated_at, ssh_target_id,COALESCE(user_id,0),source_task_id`

func scanConv(row interface{ Scan(...any) error }) (Conversation, error) {
	var c Conversation
	var pinnedAt sql.NullTime
	err := row.Scan(&c.ID, &c.AccountID, &c.AgentKey, &c.Title, &c.LLMProfileID, &pinnedAt, &c.CreatedAt, &c.UpdatedAt, &c.SSHTargetID, &c.UserID, &c.SourceTaskID)
	if pinnedAt.Valid {
		c.Pinned = true
		c.PinnedAt = &pinnedAt.Time
	}
	return c, err
}

// CreateConversation opens a new chat thread for agentKey with an initial title,
// owned by accountID (the RLS policy on conversations checks this column — see
// schema.sql §Z3). llmProfileID may be nil to use the globally active profile.
func (d *DB) CreateConversation(accountID int64, agentKey, title string, llmProfileID *int64, users ...int64) (*Conversation, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if accountID <= 0 || (d.hasAccount && accountID != d.accountID) {
		return nil, sql.ErrNoRows
	}
	if llmProfileID != nil {
		owner, err := d.ProfileAccountID(*llmProfileID)
		if err != nil || owner != accountID {
			return nil, ErrLLMProfileNotFound
		}
	}
	userID := int64(0)
	if len(users) > 0 {
		userID = users[0]
	}
	if userID > 0 {
		var owned bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND account_id=$2)`, userID, accountID).Scan(&owned); err != nil {
			return nil, err
		}
		if !owned {
			return nil, sql.ErrNoRows
		}
	}
	tx, existing := d.Querier.(*sql.Tx)
	var err error
	if !existing {
		tx, err = d.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
	}

	// Insert the child without a profile first. The new row is exclusively owned
	// by this transaction before it takes a profile lock, matching DeleteProfile's
	// child-row -> profile-row protocol.
	c, err := scanConv(tx.QueryRow(`
INSERT INTO conversations(account_id, agent_key, title, llm_profile_id,user_id) VALUES ($1, $2, $3, NULL,$4)
RETURNING `+convCols, accountID, agentKey, title, nullIfZero(userID)))
	if err != nil {
		return nil, err
	}
	if err := lockLLMProfileForReference(tx, llmProfileID); err != nil {
		return nil, err
	}
	if llmProfileID != nil {
		c, err = scanConv(tx.QueryRow(`UPDATE conversations SET llm_profile_id=$2
WHERE `+d.tenantSQL("")+` AND id=$1 RETURNING `+convCols, c.ID, llmProfileID))
		if err != nil {
			return nil, err
		}
	}
	if !existing {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// UpdateConversationProfile sets (or clears) the LLM profile override for a conversation.
func (d *DB) UpdateConversationProfile(id int64, llmProfileID *int64) error {
	c, err := d.GetConversation(id)
	if err != nil {
		return err
	}
	if c == nil {
		return sql.ErrNoRows
	}
	if llmProfileID != nil {
		owner, err := d.ProfileAccountID(*llmProfileID)
		if err != nil || owner != c.AccountID {
			return ErrLLMProfileNotFound
		}
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var lockedID int64
	if err := tx.QueryRow(`SELECT id FROM conversations WHERE `+d.tenantSQL("")+` AND id=$1 FOR UPDATE`, id).Scan(&lockedID); err != nil {
		if err == sql.ErrNoRows {
			// Preserve the previous UPDATE semantics: an unknown id is a no-op.
			return tx.Commit()
		}
		return err
	}
	if err := lockLLMProfileForReference(tx, llmProfileID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE conversations SET llm_profile_id=$2 WHERE `+d.tenantSQL("")+` AND id=$1`, id, llmProfileID); err != nil {
		return err
	}
	return tx.Commit()
}

// ListConversations returns all threads, most-recently-updated first.
func (d *DB) ListConversations() ([]*Conversation, error) {
	rows, err := d.Query(`SELECT ` + convCols + ` FROM conversations WHERE ` + d.tenantSQL("") + `
ORDER BY (pinned_at IS NOT NULL) DESC, pinned_at DESC NULLS LAST, updated_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Conversation{}
	for rows.Next() {
		c, err := scanConv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// GetConversation returns one thread (nil, nil if absent).
func (d *DB) GetConversation(id int64) (*Conversation, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("conversation", id)
	}
	c, err := scanConv(d.QueryRow(`SELECT `+convCols+` FROM conversations WHERE `+d.tenantSQL("")+` AND id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateConversation applies a partial title/pin mutation and returns the updated
// row. Pinning an already-pinned conversation preserves its original pin order.
func (d *DB) UpdateConversation(id int64, patch ConversationPatch) (*Conversation, error) {
	c, err := scanConv(d.QueryRow(`UPDATE conversations SET
	title = CASE WHEN $2::boolean THEN $3 ELSE title END,
	pinned_at = CASE
		WHEN $4::boolean IS NULL THEN pinned_at
		WHEN $4::boolean THEN COALESCE(pinned_at, now())
		ELSE NULL
	END
WHERE `+d.tenantSQL("")+` AND id=$1
RETURNING `+convCols, id, patch.Title != nil, patch.Title, patch.Pinned))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// RenameConversation sets a thread's title. Kept for automatic first-message
// titles and compatibility with existing callers.
func (d *DB) RenameConversation(id int64, title string) error {
	_, err := d.UpdateConversation(id, ConversationPatch{Title: &title})
	return err
}

// TouchConversation bumps updated_at so the thread floats to the top of the list.
func (d *DB) TouchConversation(id int64) error {
	_, err := d.Exec(`UPDATE conversations SET updated_at=now() WHERE `+d.tenantSQL("")+` AND id=$1`, id)
	return err
}

func (d *DB) SetConversationExecutor(accountID, id int64, targetID *int64) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	if d.hasAccount && d.accountID != accountID {
		return sql.ErrNoRows
	}
	if targetID != nil {
		if _, err := d.GetSSHTarget(accountID, *targetID); err != nil {
			return err
		}
	}
	res, err := d.Exec(`UPDATE conversations SET ssh_target_id=$3 WHERE account_id=$1 AND id=$2`, accountID, id, targetID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

// DeleteConversation removes a thread; its activities cascade via FK.
func (d *DB) DeleteConversation(id int64) error {
	_, err := d.Exec(`WITH removed AS (DELETE FROM conversations WHERE `+d.tenantSQL("")+` AND id=$1 RETURNING account_id,id) DELETE FROM account_settings s USING removed r WHERE s.account_id=r.account_id AND s.key='conversation.credentials.'||r.id::text`, id)
	return err
}

// DeleteConversations removes existing threads in one statement and returns the
// ids that were actually present. Child activities and trigger runs cascade.
func (d *DB) DeleteConversations(ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return []int64{}, nil
	}
	rows, err := d.Query(`WITH removed AS (DELETE FROM conversations WHERE `+d.tenantSQL("")+` AND id=ANY($1::bigint[]) RETURNING account_id,id), cleanup AS (DELETE FROM account_settings s USING removed r WHERE s.account_id=r.account_id AND s.key='conversation.credentials.'||r.id::text) SELECT id FROM removed`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deleted := make([]int64, 0, len(ids))
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		deleted = append(deleted, id)
	}
	return deleted, rows.Err()
}

// AppendConvActivity records one step of a conversation (human message or an agent
// execution step) and returns its id. Mirrors ExplorationStore.AppendActivity but
// keyed by conversation_id. Reuses the Activity struct (NodeID is ignored here).
func (d *DB) AppendConvActivity(convID int64, a Activity) (int64, error) {
	if d.hasAccount {
		c, err := d.GetConversation(convID)
		if err != nil || c == nil {
			return 0, sql.ErrNoRows
		}
		creds, err := d.ConversationCredentials(convID)
		if err != nil {
			return 0, err
		}
		for _, credential := range creds {
			if credential.Password != "" {
				a.Summary = strings.ReplaceAll(a.Summary, credential.Password, evidenceredact.Mask)
				a.Detail = strings.ReplaceAll(a.Detail, credential.Password, evidenceredact.Mask)
			}
		}
	}
	a.Summary = evidenceredact.Text(a.Summary)
	a.Detail = evidenceredact.Text(a.Detail)
	var id int64
	err := d.QueryRow(`
INSERT INTO conversation_activities(conversation_id, worker, kind, tool, tool_use_id, is_error, summary, detail, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
VALUES ($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12)
RETURNING id`, convID, utf8Clean(a.Worker), utf8Clean(a.Kind), utf8Clean(a.Tool), utf8Clean(a.ToolUseID), a.IsError,
		utf8Clean(a.Summary), utf8Clean(a.Detail), a.InputTokens, a.OutputTokens, a.CacheReadTokens, a.CacheWriteTokens).Scan(&id)
	return id, err
}

// ConvActivityList returns a conversation's steps after sinceID (exclusive) with
// the summary-only column set (detail is lazy-loaded via ConvActivityDetail).
func (d *DB) ConvActivityList(convID, sinceID int64, limit int) ([]Activity, int64, error) {
	if d.hasAccount {
		c, err := d.GetConversation(convID)
		if err != nil || c == nil {
			return nil, sinceID, sql.ErrNoRows
		}
	}
	if limit <= 0 {
		limit = 500
	}
	const cols = `id, COALESCE(worker,''), COALESCE(kind,''), COALESCE(tool,''), COALESCE(tool_use_id,''), is_error, COALESCE(summary,''), created_at, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens`
	rows, err := d.Query(`SELECT `+cols+`
FROM conversation_activities WHERE conversation_id=$1 AND id>$2 ORDER BY id LIMIT $3`, convID, sinceID, limit)
	if err != nil {
		return nil, sinceID, err
	}
	defer rows.Close()
	out := []Activity{}
	cursor := sinceID
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.Worker, &a.Kind, &a.Tool, &a.ToolUseID, &a.IsError, &a.Summary, &a.CreatedAt,
			&a.InputTokens, &a.OutputTokens, &a.CacheReadTokens, &a.CacheWriteTokens); err != nil {
			return nil, sinceID, err
		}
		if a.ID > cursor {
			cursor = a.ID
		}
		out = append(out, a)
	}
	return out, cursor, rows.Err()
}

// ConvActivityPage returns one page for reverse (newest-first) pagination: up to
// `limit` steps ending before id `before` (exclusive; before<=0 = the latest
// page), returned in ASCENDING id order. hasMore reports whether still-older steps
// exist before the returned window, so the client can stop loading earlier history
// on scroll-up. Summary-only columns (detail is lazy-loaded via ConvActivityDetail).
func (d *DB) ConvActivityPage(convID, before int64, limit int) ([]Activity, bool, error) {
	if d.hasAccount {
		c, err := d.GetConversation(convID)
		if err != nil || c == nil {
			return nil, false, sql.ErrNoRows
		}
	}
	if limit <= 0 {
		limit = 200
	}
	const cols = `id, COALESCE(worker,''), COALESCE(kind,''), COALESCE(tool,''), COALESCE(tool_use_id,''), is_error, COALESCE(summary,''), created_at, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens`
	// fetch one extra row to detect whether older history remains before this window.
	rows, err := d.Query(`SELECT `+cols+`
FROM conversation_activities
WHERE conversation_id=$1 AND ($2 <= 0 OR id < $2)
ORDER BY id DESC LIMIT $3`, convID, before, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	desc := []Activity{}
	for rows.Next() {
		var a Activity
		if err := rows.Scan(&a.ID, &a.Worker, &a.Kind, &a.Tool, &a.ToolUseID, &a.IsError, &a.Summary, &a.CreatedAt,
			&a.InputTokens, &a.OutputTokens, &a.CacheReadTokens, &a.CacheWriteTokens); err != nil {
			return nil, false, err
		}
		desc = append(desc, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(desc) > limit
	if hasMore {
		desc = desc[:limit]
	}
	// reverse the newest-first window into ascending id order for display.
	out := make([]Activity, len(desc))
	for i, a := range desc {
		out[len(desc)-1-i] = a
	}
	return out, hasMore, nil
}

// ConvActivityDetail lazily returns the full detail blob for one step.
func (d *DB) ConvActivityDetail(convID, id int64) (string, error) {
	if d.hasAccount {
		c, err := d.GetConversation(convID)
		if err != nil || c == nil {
			return "", sql.ErrNoRows
		}
	}
	var s sql.NullString
	err := d.QueryRow(`SELECT detail FROM conversation_activities WHERE id=$1 AND conversation_id=$2`, id, convID).Scan(&s)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return s.String, err
}

// BindTriggeredConversation inherits execution configuration only from its owned source task.
func (d *DB) BindTriggeredConversation(accountID, convID, taskID int64) error {
	if accountID <= 0 || (d.hasAccount && d.accountID != accountID) {
		return sql.ErrNoRows
	}
	d = d.ForAccount(accountID)
	res, err := d.Exec(`UPDATE conversations c SET source_task_id=t.id,ssh_target_id=t.ssh_target_id,user_id=t.user_id,llm_profile_id=t.active_llm_profile_id FROM tasks t WHERE c.id=$1 AND c.account_id=$2 AND t.id=$3 AND t.account_id=c.account_id AND t.deleted_at IS NULL`, convID, accountID, taskID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return sql.ErrNoRows
	}
	return err
}
