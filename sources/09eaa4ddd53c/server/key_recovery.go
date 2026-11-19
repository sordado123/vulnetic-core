package server

import (
	"errors"
	"fmt"
	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/db"
	"os"
	"path/filepath"
	"strings"
)

func validateKeyRecovery(pg *db.DB, keyDir, dataDir string) error {
	if !config.SaaSMode() {
		return nil
	}
	jwtMissing := false
	vaultMissing := false
	missing := func(name string) (bool, error) {
		_, err := os.Stat(name)
		if err == nil {
			return false, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	var err error
	jwtMissing, err = missing(filepath.Join(keyDir, jwtKeyFilename))
	if err != nil {
		return err
	}
	if jwtMissing {
		jwtMissing, err = missing(filepath.Join(dataDir, jwtKeyFilename))
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(os.Getenv("VULNETIC_VAULT_KEY")) == "" {
		vaultMissing, err = missing(filepath.Join(keyDir, "vault.key"))
		if err != nil {
			return err
		}
	}
	if !jwtMissing && !vaultMissing {
		return nil
	}
	ids, err := pg.RuntimeAccountIDs()
	if err != nil {
		return fmt.Errorf("key recovery check unavailable: %w", err)
	}
	for _, id := range ids {
		var users, keys bool
		err := pg.ForAccount(id).QueryRow(`SELECT EXISTS(SELECT 1 FROM users),EXISTS(SELECT 1 FROM account_vault_keys)`).Scan(&users, &keys)
		if err != nil {
			return fmt.Errorf("key recovery check unavailable: %w", err)
		}
		if (jwtMissing && users) || (vaultMissing && keys) {
			return errors.New("required key is missing from an initialized installation; restore the original JWT/vault backup before startup")
		}
	}
	return nil
}
