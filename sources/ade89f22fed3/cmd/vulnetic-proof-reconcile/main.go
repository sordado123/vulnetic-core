package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sordado123/vulnetic/db"
	"github.com/sordado123/vulnetic/server"
	"github.com/sordado123/vulnetic/vault"
)

func main() {
	account := flag.Int64("account", 0, "explicit account to inspect")
	data := flag.String("data", "", "existing platform data directory")
	keys := flag.String("key-dir", "", "directory containing the existing vault.key")
	recover := flag.Bool("recover", false, "recover attributable unregistered proofs; default is inspection")
	flag.Parse()
	if err := run(*account, *data, *keys, *recover); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(account int64, data, keys string, recover bool) error {
	if account <= 0 || data == "" || os.Getenv("VULNETIC_PG_DSN") == "" {
		return fmt.Errorf("provide account, existing data directory and limited runtime DSN in VULNETIC_PG_DSN")
	}
	if os.Getenv("VULNETIC_VAULT_KEY") == "" {
		if _, err := os.Stat(filepath.Join(keys, "vault.key")); err != nil {
			return fmt.Errorf("existing vault key is required")
		}
	}
	key, err := vault.LoadOrCreateMasterKey(keys)
	if err != nil {
		return err
	}
	pg, err := db.OpenRuntime(os.Getenv("VULNETIC_PG_DSN"))
	if err != nil {
		return err
	}
	defer pg.Close()
	pg.ConfigureVault(key, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := server.ReconcileProofArtifacts(ctx, pg, key, data, account, recover)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
