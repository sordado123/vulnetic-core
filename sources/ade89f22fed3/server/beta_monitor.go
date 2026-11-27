package server

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/internal/artifactquota"
)

type betaMetrics struct {
	Time             time.Time        `json:"time"`
	Running          int              `json:"running_tasks"`
	Queued           int              `json:"queued_tasks"`
	SSH              int              `json:"ssh_executors"`
	SSHSessions      int              `json:"ssh_sessions"`
	Agents           int              `json:"agent_connections"`
	OwnerPool        map[string]int64 `json:"owner_pool"`
	AppPool          map[string]int64 `json:"app_pool"`
	Storage          map[string]int64 `json:"account_storage_bytes"`
	StorageErrors    int              `json:"storage_errors"`
	EvidenceFailures uint64           `json:"evidence_failures"`
}

func poolMetrics(pg *db.DB) map[string]int64 {
	if pg == nil {
		return nil
	}
	stats := pg.PoolStats()
	return map[string]int64{"open": int64(stats.OpenConnections), "in_use": int64(stats.InUse), "idle": int64(stats.Idle), "max": int64(stats.MaxOpenConnections), "wait_count": stats.WaitCount, "wait_ms": stats.WaitDuration.Milliseconds()}
}

func (s *Server) betaSnapshot() betaMetrics {
	metrics := betaMetrics{Time: time.Now().UTC(), OwnerPool: poolMetrics(s.m.pg), AppPool: poolMetrics(s.m.pgApp), Storage: map[string]int64{}, EvidenceFailures: s.evidenceFailures.Load()}
	for _, task := range s.m.List() {
		state := task.lifecycleSnapshot()
		if state.Queued {
			metrics.Queued++
		} else if !state.Paused && !isTerminalStatus(state.Status) {
			metrics.Running++
		}
	}
	s.remoteMu.Lock()
	metrics.Agents = len(s.agentConnections)
	metrics.SSH = len(s.remoteExecutors)
	for executor := range s.remoteExecutors {
		metrics.SSHSessions += executor.ActiveSessions()
	}
	s.remoteMu.Unlock()
	root, err := os.OpenRoot(filepath.Join(s.m.dir, "accounts"))
	if os.IsNotExist(err) {
		return metrics
	}
	if err != nil {
		metrics.StorageErrors++
		return metrics
	}
	defer root.Close()
	entries, err := rootReadDir(root, ".")
	if err != nil {
		metrics.StorageErrors++
		return metrics
	}
	for _, entry := range entries {
		id, err := strconv.ParseInt(entry.Name(), 10, 64)
		if err != nil || id <= 0 || !entry.IsDir() {
			continue
		}
		account, err := root.OpenRoot(entry.Name())
		if err != nil {
			metrics.StorageErrors++
			continue
		}
		size, err := artifactquota.Bytes(account)
		account.Close()
		if err != nil {
			metrics.StorageErrors++
			continue
		}
		metrics.Storage[entry.Name()] = size
	}
	return metrics
}

// Operator stdout only: customer log APIs are unavailable in SaaS mode.
func (s *Server) monitorBeta(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		data, err := json.Marshal(s.betaSnapshot())
		if err == nil {
			log.Printf("[beta-metrics] %s", data)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
