// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
// Package transcript persists a conversation to an append-only JSONL log on
// disk and reconstructs it for resume. The main session is written to
// <dir>/<sessionID>.jsonl; each
// subagent is written to its own sidechain file under
// <dir>/<sessionID>/subagents/agent-<agentID>.jsonl, so subagent tokens are
// counted and stored separately (aggregate them offline if needed).
//
// The log is the full-fidelity history: every user/assistant/tool message is
// recorded as it is born. When compaction inserts a boundary, the post-boundary
// working set — the boundary marker, the summary, and the kept recent tail — is
// ALSO persisted as messages, so a cold-start resume restores the COMPACTED view
// (via llm.MessagesForAPI, which slices from the last boundary) instead of
// replaying raw history and re-summarizing. The kept tail
// is re-recorded after the boundary (it also exists earlier as births); only the
// post-boundary copy reaches the model. Lightweight working-set edits that do not
// add a boundary (MicroCompact tool-result clearing) stay ephemeral and
// are not persisted. A separate Type=="boundary" record is written for
// observability and is skipped during reconstruction.
package transcript

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sordado123/vulnetic/internal/artifactquota"
	"github.com/sordado123/vulnetic/internal/norma/llm"
)

// Record is one line of a JSONL transcript.
type Record struct {
	UUID        string            `json:"uuid"`
	ParentUUID  string            `json:"parent_uuid,omitempty"`
	SessionID   string            `json:"session_id"`
	AgentID     string            `json:"agent_id,omitempty"`
	IsSidechain bool              `json:"is_sidechain,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Type        string            `json:"type"` // "message" | "boundary"
	Message     *llm.Message      `json:"message,omitempty"`
	Usage       *llm.Usage        `json:"usage,omitempty"`    // assistant turns only
	Boundary    *llm.BoundaryMeta `json:"boundary,omitempty"` // Type=="boundary"
}

// Store is a directory of session transcripts.
type Store struct {
	dir       string
	quotaRoot string
	legacyDir string
	mu        sync.Mutex // serializes appends across writers in this process
}

// NewStore returns a Store rooted at dir (created lazily on first write).
func NewStore(dir string) *Store { return &Store{dir: dir} }

// NewAccountStore confines new transcripts to the account and preserves readable legacy history.
func NewAccountStore(dir, quotaRoot, legacyDir string) *Store {
	return &Store{dir: dir, quotaRoot: quotaRoot, legacyDir: legacyDir}
}

// MainPath is the JSONL file for a top-level session.
func (s *Store) MainPath(sessionID string) string {
	return filepath.Join(s.dir, sessionID+".jsonl")
}

// AgentPath is the sidechain JSONL file for a subagent of a session.
func (s *Store) AgentPath(sessionID, agentID string) string {
	return filepath.Join(s.dir, sessionID, "subagents", "agent-"+agentID+".jsonl")
}

// Append writes records to path as JSONL, creating parent directories. It is
// safe for concurrent use within the process.
func (s *Store) Append(path string, recs ...Record) error {
	if len(recs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quotaRoot != "" {
		var payload bytes.Buffer
		encoder := json.NewEncoder(&payload)
		for _, record := range recs {
			if err := encoder.Encode(record); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(s.quotaRoot, 0700); err != nil {
			return err
		}
		root, err := os.OpenRoot(s.quotaRoot)
		if err != nil {
			return err
		}
		defer root.Close()
		rel, err := filepath.Rel(s.quotaRoot, path)
		if err != nil || !filepath.IsLocal(rel) {
			return fmt.Errorf("transcript path escapes account storage")
		}
		return artifactquota.Write(root, rel, int64(payload.Len()), true, func() error {
			if err := root.MkdirAll(filepath.Dir(rel), 0700); err != nil {
				return err
			}
			file, err := root.OpenFile(rel, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				return err
			}
			_, err = file.Write(payload.Bytes())
			if err == nil {
				err = file.Sync()
			}
			if err != nil {
				_ = file.Truncate(info.Size())
			}
			closeErr := file.Close()
			if err != nil {
				return err
			}
			return closeErr
		})
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

// Load reads all records from a transcript file. A missing file yields no
// records and no error (a fresh session).
func (s *Store) Load(path string) ([]Record, error) {
	if s.quotaRoot == "" {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return readRecords(file)
	}
	rel, err := filepath.Rel(s.quotaRoot, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("transcript path escapes account storage")
	}
	root, err := os.OpenRoot(s.quotaRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var file *os.File
	if root != nil {
		defer root.Close()
		file, err = root.Open(rel)
	}
	if err == nil {
		defer file.Close()
		return readRecords(file)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.legacyDir == "" {
		return nil, nil
	}
	legacyRel, err := filepath.Rel(s.dir, path)
	if err != nil || !filepath.IsLocal(legacyRel) {
		return nil, fmt.Errorf("invalid legacy transcript path")
	}
	legacy, err := os.OpenRoot(s.legacyDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer legacy.Close()
	file, err = legacy.Open(legacyRel)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	records, err := readRecords(file)
	if err != nil {
		return nil, err
	}
	if err = s.Append(path, records...); err != nil {
		return nil, err
	}
	return records, nil
}

func readRecords(file io.Reader) ([]Record, error) {
	var recs []Record
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("transcript: corrupt line: %w", err)
		}
		recs = append(recs, record)
	}
	return recs, sc.Err()
}

func (s *Store) Strict() bool { return s.quotaRoot != "" }

// Messages reconstructs the raw conversation and cumulative usage from records.
// Boundary records are skipped — the working set is rebuilt by compaction on the
// next turn, not replayed from disk.
func Messages(recs []Record) ([]llm.Message, llm.Usage) {
	var msgs []llm.Message
	var total llm.Usage
	for _, r := range recs {
		if r.Type == "boundary" || r.Message == nil {
			continue
		}
		msgs = append(msgs, *r.Message)
		if r.Usage != nil {
			total.Add(*r.Usage)
		}
	}
	return msgs, total
}

// LastUUID returns the UUID of the last record, for continuing the parent chain.
func LastUUID(recs []Record) string {
	if len(recs) == 0 {
		return ""
	}
	return recs[len(recs)-1].UUID
}

// Writer binds a Store, a file path, and a session/agent identity, assigning a
// UUID and parent link to each record. It satisfies harness.Recorder. Append
// errors are retained (see Err) rather than panicking, so a failing disk
// degrades to in-memory operation instead of crashing the agent loop.
type Writer struct {
	store       *Store
	path        string
	sessionID   string
	agentID     string
	isSidechain bool

	mu   sync.Mutex
	last string
	now  func() time.Time
	err  error
}

// NewWriter returns a Writer for a fresh transcript file. agentID == "" writes
// the main session file; a non-empty agentID writes a subagent sidechain.
func (s *Store) NewWriter(sessionID, agentID string) *Writer {
	w := &Writer{store: s, sessionID: sessionID, agentID: agentID, now: time.Now}
	if agentID == "" {
		w.path = s.MainPath(sessionID)
	} else {
		w.path = s.AgentPath(sessionID, agentID)
		w.isSidechain = true
	}
	return w
}

// ResumeWriter returns a Writer that continues an existing main-session file,
// chaining new records after lastUUID.
func (s *Store) ResumeWriter(sessionID, lastUUID string) *Writer {
	w := s.NewWriter(sessionID, "")
	w.last = lastUUID
	return w
}

// Err returns the first append error encountered, if any.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *Writer) write(r Record) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r.SessionID = w.sessionID
	r.AgentID = w.agentID
	r.IsSidechain = w.isSidechain
	r.UUID = newID()
	r.ParentUUID = w.last
	r.Timestamp = w.now().UTC().Format(time.RFC3339Nano)
	if err := w.store.Append(w.path, r); err != nil {
		if w.err == nil {
			w.err = err
		}
		return
	}
	w.last = r.UUID
}

// RecordMessage persists a conversation message. usage is attributed to this
// turn (zero for non-assistant messages).
func (w *Writer) RecordMessage(m llm.Message, usage llm.Usage) {
	rec := Record{Type: "message", Message: &m}
	if usage != (llm.Usage{}) {
		u := usage
		rec.Usage = &u
	}
	w.write(rec)
}

// RecordBoundary persists a compaction boundary for observability.
func (w *Writer) RecordBoundary(meta llm.BoundaryMeta) {
	m := meta
	w.write(Record{Type: "boundary", Boundary: &m})
}

// newID returns a random 128-bit hex identifier.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand should never fail; fall back to a time-based id to stay unique-ish.
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// NewSessionID returns a fresh session identifier.
func NewSessionID() string { return newID() }

// NewAgentID returns a fresh subagent identifier.
func NewAgentID() string { return newID() }
