package transcript

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ScanPage struct {
	NextCursor       int64 `json:"next_cursor"`
	End              bool  `json:"end"`
	ScannedBytes     int64 `json:"scanned_bytes"`
	SkippedOversized int   `json:"skipped_oversized_records"`
}

// ScanSession reads only the bound account's main transcript, never legacy/global paths.
// Byte cursors are record boundaries in this one file, not selectable paths/sessions.
func (s *Store) ScanSession(ctx context.Context, session string, cursor int64, visit func(Record, int64) bool) (page ScanPage, err error) {
	if !s.Strict() || session == "" || strings.ContainsAny(session, `/\`+"\x00") || session == "." || session == ".." || cursor < 0 {
		return page, fmt.Errorf("account-scoped transcript required")
	}
	root, err := os.OpenRoot(s.quotaRoot)
	if errors.Is(err, os.ErrNotExist) {
		return page, fmt.Errorf("current transcript storage is unavailable")
	}
	if err != nil {
		return page, fmt.Errorf("scoped transcript storage could not be opened")
	}
	defer root.Close()
	rel, err := filepath.Rel(s.quotaRoot, s.MainPath(session))
	if err != nil || !filepath.IsLocal(rel) {
		return page, fmt.Errorf("transcript path escapes account")
	}
	file, err := root.Open(rel)
	if errors.Is(err, os.ErrNotExist) {
		return page, fmt.Errorf("current transcript is unavailable")
	}
	if err != nil {
		return page, fmt.Errorf("current transcript could not be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return page, fmt.Errorf("current transcript metadata is unavailable")
	}
	if !info.Mode().IsRegular() || cursor > info.Size() {
		return page, fmt.Errorf("invalid transcript cursor")
	}
	if cursor > 0 {
		var previous [1]byte
		if _, err = file.ReadAt(previous[:], cursor-1); err != nil || previous[0] != '\n' {
			return page, fmt.Errorf("cursor must identify a complete record boundary")
		}
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(file, cursor, info.Size()-cursor), 64<<10)
	position := cursor
	for position < info.Size() {
		start := position
		var line []byte
		oversized := false
		for {
			if err := ctx.Err(); err != nil {
				return page, err
			}
			chunk, readErr := reader.ReadSlice('\n')
			position += int64(len(chunk))
			if len(line)+len(chunk) > 4<<20 {
				oversized = true
				line = nil
			}
			if !oversized {
				line = append(line, chunk...)
			}
			if readErr == bufio.ErrBufferFull {
				continue
			}
			if readErr == io.EOF {
				return page, fmt.Errorf("transcript tail is incomplete; retry after the current write")
			}
			if readErr != nil && readErr != io.EOF {
				return page, fmt.Errorf("current transcript could not be read")
			}
			break
		}
		page.NextCursor, page.ScannedBytes = position, position-cursor
		if oversized {
			page.SkippedOversized++
		} else if len(strings.TrimSpace(string(line))) > 0 {
			var record Record
			if json.Unmarshal(line, &record) != nil || record.SessionID != session || record.IsSidechain || record.AgentID != "" {
				return page, fmt.Errorf("invalid record in current transcript")
			}
			if record.Type == "message" && record.Message != nil && !visit(record, start) {
				break
			}
		}
		if page.ScannedBytes >= 16<<20 {
			break
		}
	}
	page.End = position >= info.Size()
	return page, nil
}
