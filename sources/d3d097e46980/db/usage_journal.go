package db

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type usageJournal struct {
	root   *os.Root
	failed sync.Map
}
type usageEnvelope struct {
	AccountID int64    `json:"account_id"`
	Usage     LLMUsage `json:"usage"`
}

// ConfigureUsageJournal keeps only metering dimensions, outside customer artifacts and HTTP file APIs.
func (d *DB) ConfigureUsageJournal(ctx context.Context, directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	d.usageJournal = &usageJournal{root: root}
	go func() {

		d.replayUsage()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.replayUsage()
			}
		}
	}()
	return nil
}
func (d *DB) UsagePending(accountID int64) (int, error) {
	if d.usageJournal == nil {
		return 0, nil
	}
	dir, err := d.usageJournal.root.Open(strconv.FormatInt(accountID, 10))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return 0, errors.New("usage journal needs operator review")
		}
		if strings.HasSuffix(entry.Name(), ".json") || strings.Contains(entry.Name(), ".json.tmp-") {
			count++
		}
	}
	if _, failed := d.usageJournal.failed.Load(accountID); failed {
		return count, errors.New("usage journal requires recovery")
	}
	return count, nil
}
func (d *DB) UsageMeteringReady(accountID int64) error {
	pending, err := d.UsagePending(accountID)
	if err != nil {
		return err
	}
	if pending >= 10000 {
		return errors.New("usage persistence backlog is full; wait for database recovery")
	}
	return nil
}
func (d *DB) journalUsage(u *LLMUsage) error {
	j := d.usageJournal
	directory := strconv.FormatInt(u.AccountID, 10)
	if _, err := uuid.Parse(u.CallID); err != nil {
		return err
	}
	if err := j.root.MkdirAll(directory, 0700); err != nil {
		j.failed.Store(u.AccountID, true)
		return err
	}
	blob, err := json.Marshal(usageEnvelope{u.AccountID, *u})
	if err != nil {
		return err
	}
	name := filepath.Join(directory, u.CallID+".json")
	temporary := name + ".tmp-" + uuid.NewString()
	file, err := j.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		j.failed.Store(u.AccountID, true)
		return err
	}
	_, err = file.Write(blob)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = j.root.Rename(temporary, name)
	}
	if err != nil {
		j.failed.Store(u.AccountID, true)
		_ = j.root.Remove(temporary)
		return err
	}
	directoryFile, syncErr := j.root.Open(directory)
	if syncErr == nil {
		syncErr = directoryFile.Sync()
		directoryFile.Close()
	}
	if syncErr != nil {
		j.failed.Store(u.AccountID, true)
		return syncErr
	}
	if err = d.insertLLMUsage(u); err != nil {
		return err
	}
	err = j.root.Remove(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (d *DB) replayUsage() {
	j := d.usageJournal
	dir, err := j.root.Open(".")
	if err != nil {
		return
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return
	}
	for _, entry := range entries {
		accountID, err := strconv.ParseInt(entry.Name(), 10, 64)
		if err != nil || accountID <= 0 || !entry.IsDir() {
			continue
		}
		directory := entry.Name()
		folder, err := j.root.Open(directory)
		if err != nil {
			j.failed.Store(accountID, true)
			continue
		}
		files, err := folder.ReadDir(-1)
		folder.Close()
		if err != nil {
			j.failed.Store(accountID, true)
			continue
		}
		corrupt := false
		for _, file := range files {
			if strings.Contains(file.Name(), ".json.tmp-") {
				info, e := file.Info()
				if e == nil && time.Since(info.ModTime()) > time.Minute {
					j.failed.Store(accountID, true)
					corrupt = true
				}
				continue
			}
			if !file.Type().IsRegular() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			name := filepath.Join(directory, file.Name())
			f, err := j.root.Open(name)
			if err != nil {
				continue
			}
			blob, err := io.ReadAll(io.LimitReader(f, 65537))
			f.Close()
			var envelope usageEnvelope
			if err != nil || len(blob) > 65536 || json.Unmarshal(blob, &envelope) != nil || envelope.AccountID != accountID || envelope.Usage.CallID+".json" != file.Name() {
				j.failed.Store(accountID, true)
				corrupt = true
				log.Printf("[llmusage] journal record needs operator review for account %d", accountID)
				continue
			}
			envelope.Usage.AccountID = accountID
			pg := d.ForAccount(accountID)
			// The usage ledger intentionally survives task deletion.

			if err = pg.insertLLMUsage(&envelope.Usage); err == nil {
				_ = j.root.Remove(name)
			}
		}
		// Recover a transient filesystem failure only after a fresh synchronized write.
		if _, failed := j.failed.Load(accountID); failed && !corrupt {
			probe := filepath.Join(directory, ".probe-"+uuid.NewString())
			f, e := j.root.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e == nil {
				_, e = f.Write([]byte("probe"))
				if e == nil {
					e = f.Sync()
				}
				f.Close()
				_ = j.root.Remove(probe)
				if e == nil {
					j.failed.Delete(accountID)
				}
			}
		}
	}
}
func (d *DB) ShareUsageJournalFrom(other *DB) { d.usageJournal = other.usageJournal }
