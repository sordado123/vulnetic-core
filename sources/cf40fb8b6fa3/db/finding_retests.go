package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"strings"
	"time"
)

const FindingRetestAgentKey = "retester"

var ErrRetestNotRunning = errors.New("this retest has ended or has not started; please start a new retest from the finding details")

// FindingRetest is an immutable historical test once its conversation turn ends.
// Snapshot is only loaded for the agent, never sent with the history list.
type FindingRetest struct {
	ID             int64                `json:"id"`
	FindingID      int64                `json:"finding_id"`
	ConversationID *int64               `json:"conversation_id"`
	Status         string               `json:"status"`
	Verdict        string               `json:"verdict"`
	Notes          string               `json:"notes"`
	Snapshot       json.RawMessage      `json:"snapshot,omitempty"`
	Summary        string               `json:"summary"`
	Evidence       string               `json:"evidence"`
	Error          string               `json:"error"`
	CreatedAt      time.Time            `json:"created_at"`
	StartedAt      *time.Time           `json:"started_at"`
	FinishedAt     *time.Time           `json:"finished_at"`
	ReviewRequired bool                 `json:"review_required"`
	Review         *FindingRetestReview `json:"review,omitempty"`
}

type FindingRetestReview struct {
	UserID     int64     `json:"user_id"`
	Steps      string    `json:"steps"`
	ProofIDs   []int64   `json:"proof_ids"`
	ReviewedAt time.Time `json:"reviewed_at"`
}

const retestCols = `id, finding_id, conversation_id, status, verdict, notes, summary, evidence, error, created_at, started_at, finished_at,
(SELECT to_jsonb(review) FROM finding_retest_reviews review WHERE review.retest_id=finding_retests.id)`

// ActiveFindingRetest is the small status payload polled by the findings list.
// Finding IDs use the same string representation as the findings API.
type ActiveFindingRetest struct {
	ID             int64  `json:"id"`
	FindingID      int64  `json:"finding_id,string"`
	ConversationID int64  `json:"conversation_id"`
	Status         string `json:"status"`
}

func (d *DB) ListActiveFindingRetests(ctx context.Context, accountID int64) ([]ActiveFindingRetest, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.ForAccount(accountID)
	}
	rows, err := d.QueryContext(ctx, `SELECT fr.id, fr.finding_id, fr.conversation_id, fr.status
	FROM finding_retests fr
	JOIN findings f ON f.id = fr.finding_id
	WHERE fr.status IN ('pending','running') AND fr.conversation_id IS NOT NULL AND f.account_id = $1
	ORDER BY fr.id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ActiveFindingRetest{}
	for rows.Next() {
		var item ActiveFindingRetest
		if err := rows.Scan(&item.ID, &item.FindingID, &item.ConversationID, &item.Status); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanRetest(row interface{ Scan(...any) error }) (*FindingRetest, error) {
	r := &FindingRetest{}
	var review []byte
	err := row.Scan(&r.ID, &r.FindingID, &r.ConversationID, &r.Status, &r.Verdict, &r.Notes,
		&r.Summary, &r.Evidence, &r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &review)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err == nil && len(review) > 0 {
		err = json.Unmarshal(review, &r.Review)
	}
	r.ReviewRequired = config.SaaSMode() && r.Review == nil && (r.Verdict == "fixed" || r.Verdict == "reproduced")
	return r, err
}

// CreateFindingRetest atomically snapshots the source, creates its conversation
// and persists the first message. A finding row lock deduplicates simultaneous
// clicks across clients; an existing active run is returned without dispatching.
func (d *DB) CreateFindingRetest(ctx context.Context, findingID int64, notes string) (*FindingRetest, *Conversation, bool, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("finding", findingID)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer tx.Rollback()
	actor := ExecutionOwnerFrom(ctx)
	var title string
	var accountID int64
	var targetID, profileID *int64
	var snapshot []byte
	err = tx.QueryRowContext(ctx, `SELECT f.account_id,(SELECT ssh_target_id FROM tasks WHERE id=f.task_id),(SELECT COALESCE(active_llm_profile_id,llm_profile_id) FROM tasks WHERE id=f.task_id),COALESCE(NULLIF(f.name,''), NULLIF(f.vulnclass,''), 'Uncategorized'),
	jsonb_build_object('finding', to_jsonb(f),
	 'assets', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM assets a WHERE a.account_id=f.account_id AND f.asset_ids @> to_jsonb(ARRAY[a.id])), '[]'::jsonb),
	 'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id), '[]'::jsonb))
	FROM findings f WHERE f.id=$1 AND `+d.tenantSQL("f.")+` FOR UPDATE OF f`, findingID).Scan(&accountID, &targetID, &profileID, &title, &snapshot)
	if err != nil {
		return nil, nil, false, err
	}
	if actor.AccountID != 0 && actor.AccountID != accountID {
		return nil, nil, false, sql.ErrNoRows
	}
	if actor.UserID != 0 {
		var owned bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND account_id=$2)`, actor.UserID, accountID).Scan(&owned); err != nil {
			return nil, nil, false, err
		}
		if !owned {
			return nil, nil, false, sql.ErrNoRows
		}
	}
	r, err := scanRetest(tx.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 AND status IN ('pending','running')`, findingID))
	if err != nil {
		return nil, nil, false, err
	}
	if r != nil {
		return r, nil, false, nil
	}
	// Keep the title within the same limit as ordinary conversations.
	if runes := []rune(title); len(runes) > 100 {
		title = string(runes[:100])
	}
	c, err := scanConv(tx.QueryRowContext(ctx, `INSERT INTO conversations(agent_key,title,account_id,ssh_target_id,llm_profile_id,user_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+convCols,
		FindingRetestAgentKey, fmt.Sprintf("Retest #%d · %s", findingID, title), accountID, targetID, profileID, nullIfZero(actor.UserID)))
	if err != nil {
		return nil, nil, false, err
	}
	r, err = scanRetest(tx.QueryRowContext(ctx, `INSERT INTO finding_retests(finding_id,conversation_id,notes,snapshot) VALUES ($1,$2,$3,$4) RETURNING `+retestCols,
		findingID, c.ID, strings.TrimSpace(notes), snapshot))
	if err != nil {
		return nil, nil, false, err
	}
	msg := r.InitialMessage()
	_, err = tx.ExecContext(ctx, `INSERT INTO conversation_activities(conversation_id,worker,kind,summary,detail) VALUES ($1,$2,'user',$3,$4)`,
		c.ID, FindingRetestAgentKey, fmt.Sprintf("Please retest vulnerability #%d", findingID), msg)
	if err != nil {
		return nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	return r, &c, true, nil
}

func (r *FindingRetest) InitialMessage() string {
	msg := fmt.Sprintf("Please retest vulnerability #%d. First call get_finding_retest_context to read the original evidence and constraints associated with this conversation, then perform targeted verification, and finally call record_finding_retest_result to save the conclusion.", r.FindingID)
	if r.Notes != "" {
		msg += "\n\nAdditional notes for this retest:\n" + r.Notes
	}
	return msg
}

func (d *DB) ListFindingRetests(findingID int64) ([]*FindingRetest, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("finding", findingID)
	}
	rows, err := d.Query(`SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingRetest{}
	for rows.Next() {
		r, err := scanRetest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) FindingRetestForConversation(ctx context.Context, conversationID int64) (*FindingRetest, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("conversation", conversationID)
	}
	r, err := scanRetest(d.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE conversation_id=$1`, conversationID))
	if err != nil || r == nil {
		return r, err
	}
	err = d.QueryRowContext(ctx, `SELECT snapshot FROM finding_retests WHERE id=$1`, r.ID).Scan(&r.Snapshot)
	return r, err
}

// FailPendingRetestForConversation seals a conversation's unfinished retest when
// the runner could not even load it — the retest ID is unknown on that path, so
// the conversation ID is the only handle. Without it a transient read error
// leaves the row 'pending' forever: the findings list keeps showing "retesting"
// and every later retest launch is deduped against a run that is not happening,
// with only a process restart (RecoverFindingRetests) able to clear it.
func (d *DB) FailPendingRetestForConversation(conversationID int64, reason string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("conversation", conversationID)
	}
	_, err := d.Exec(`UPDATE finding_retests SET status='failed', error=$2, finished_at=now()
		WHERE conversation_id=$1 AND status IN ('pending','running')`, conversationID, reason)
	return err
}

func (d *DB) StartFindingRetest(ctx context.Context, id int64) (bool, error) {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("retest", id)
	}
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET status='running', started_at=now() WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecordFindingRetestResult never accepts a finding ID: ownership comes from the
// runtime conversation. Identical retries are safe; a second verdict is refused.
func (d *DB) RecordFindingRetestResult(ctx context.Context, conversationID int64, verdict, summary, evidence string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("conversation", conversationID)
	}
	if verdict != "reproduced" && verdict != "fixed" && verdict != "inconclusive" {
		return errors.New("verdict must be reproduced / fixed / inconclusive")
	}
	summary, evidence = strings.TrimSpace(summary), strings.TrimSpace(evidence)
	if summary == "" || evidence == "" {
		return errors.New("summary and evidence must not be empty; when the result cannot be confirmed, describe the actual checks and the blocking reason")
	}
	if len(summary) > 16000 || len(evidence) > 128000 {
		return errors.New("retest conclusion is too long (summary ≤ 16KB, evidence ≤ 128KB)")
	}
	if config.SaaSMode() && verdict != "inconclusive" {
		var hasProof bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM execution_proofs WHERE conversation_id=$1 AND `+d.tenantSQL("")+`)`, conversationID).Scan(&hasProof); err != nil {
			return err
		}
		if !hasProof {
			return errors.New("actual execution evidence is required; save an inconclusive result when blocked")
		}
	}
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET verdict=$2,summary=$3,evidence=$4
	WHERE conversation_id=$1 AND status='running' AND (verdict='' OR (verdict=$2 AND summary=$3 AND evidence=$4))`, conversationID, verdict, summary, evidence)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrRetestNotRunning
	}
	return nil
}

// FinishFindingRetest seals the result. Cancellation/failure takes precedence
// over a staged verdict so an interrupted test cannot appear successfully fixed.
// Only a newly completed fixed verdict updates triage, in the same transaction.
func (d *DB) FinishFindingRetest(id int64, status, reason string) error {
	if d.RuntimeOnly() && !d.hasAccount {
		d = d.runtimeResource("retest", id)
	}
	if status != "completed" && status != "failed" && status != "stopped" {
		return errors.New("invalid terminal retest status")
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock the finding before the retest, matching creation and cascading deletion.
	var findingID int64
	err = tx.QueryRow(`SELECT f.id FROM findings f WHERE f.id=(SELECT finding_id FROM finding_retests WHERE id=$1) FOR UPDATE OF f`, id).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // Finding/retest already deleted.
	}
	if err != nil {
		return err
	}
	var finalStatus, verdict string
	err = tx.QueryRow(`UPDATE finding_retests SET
	status=CASE WHEN $2='completed' AND verdict='' THEN 'failed' ELSE $2 END,
	error=CASE WHEN $2='completed' AND verdict='' THEN 'Agent did not save the retest conclusion; please review the conversation and retest again' ELSE $3 END,
	finished_at=now() WHERE id=$1 AND status IN ('pending','running') RETURNING status,verdict`, id, status, reason).Scan(&finalStatus, &verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A replay must not overwrite a later manual triage decision.
	}
	if err != nil {
		return err
	}
	if finalStatus == "completed" && verdict == "fixed" && !config.SaaSMode() {
		// Go through the notifying version, sharing the same semantics as a
		// manual status change on the details page.
		//
		// This used to be a bare UPDATE: when a retest verdict was "Fixed" the
		// status did change, but channels configured with on_status_change never
		// got a push — the status changed silently in the UI and operators only
		// found out by opening the platform. The status update and the push
		// event must be persisted together; SetFindingStatusTx internally
		// handles details like "do not register when the status is unchanged".
		// context.Background() is used: this whole function is the old ctx-free
		// style (d.Begin()/tx.QueryRow/tx.Exec) with no cancellation signal to
		// pass; bolting on a ctx parameter would drag in server-side call sites
		// and several tests, beyond the scope of this change.
		if _, _, _, _, err := SetFindingStatusTx(context.Background(), tx, findingID, FindingFixed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) RecoverFindingRetests() error {
	if d.RuntimeOnly() && !d.hasAccount {
		ids, err := d.RuntimeAccountIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err = d.ForAccount(id).RecoverFindingRetests(); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := d.Exec(`UPDATE finding_retests SET status='stopped', error='Server restarted; the retest was interrupted, please start it again', finished_at=now() WHERE status IN ('pending','running')`)
	return err
}
