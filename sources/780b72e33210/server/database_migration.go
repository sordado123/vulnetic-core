package server

import (
	"context"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/vault"
	"path/filepath"
)

// PrepareBetaDatabase is the only production path that receives an owner DSN.
// It never starts a listener, model, scheduler or execution engine.
func PrepareBetaDatabase(ctx context.Context, dataDir, keyDir string) error {
	dsn, _, err := db.DSN()
	if err != nil {
		return err
	}
	pg, err := db.Open(dsn)
	if err != nil {
		return err
	}
	defer pg.Close()
	if err := validateKeyRecovery(pg, keyDir, dataDir); err != nil {
		return err
	}
	key, err := vault.LoadOrCreateMasterKey(keyDir)
	if err != nil {
		return err
	}
	if _, err = loadOrCreateJWTKey(keyDir, dataDir); err != nil {
		return err
	}
	pg.ConfigureVault(key, config.SaaSMode())
	if err = pg.MigrateSecrets(); err != nil {
		return err
	}
	s := &Server{ctx: ctx, m: &Manager{pg: pg}, vaultKey: key, skillDir: filepath.Join(config.BaseDir(), "skills")}
	if err = pg.EnsureAccountCatalogs(s.seedAccountCatalog); err != nil {
		return err
	}
	return s.seedVPSDiscovery()
}
