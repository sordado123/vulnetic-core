package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaseDirUsesDedicatedStateDirectory(t *testing.T) {
	t.Setenv("VULNETIC_STATE_DIR", "")
	previous := BaseDir()
	dir := t.TempDir()
	t.Setenv("VULNETIC_STATE_DIR", dir)
	if got := BaseDir(); got != dir {
		t.Fatalf("state directory: got %q, want %q", got, dir)
	}
	t.Setenv("VULNETIC_STATE_DIR", "")
	if got := BaseDir(); got != previous {
		t.Fatalf("default directory changed: got %q, want %q", got, previous)
	}
}

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("VULNETIC_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("VULNETIC_PG_DSN", "")
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("VULNETIC_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("VULNETIC_PG_DSN", "")
	t.Setenv("VULNETIC_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("VULNETIC_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

func TestPostgresDSNDeprecatedAliasStillWorks(t *testing.T) {
	// VULNETIC_CONFIG/VULNETIC_PG_DSN unset, old ARTEX_* names still honored
	// (with a deprecation log) — protects existing deployments through the rename.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{}`), 0o644)
	t.Setenv("VULNETIC_CONFIG", "")
	t.Setenv("ARTEX_CONFIG", cfgPath)
	t.Setenv("VULNETIC_PG_DSN", "")
	t.Setenv("ARTEX_PG_DSN", "postgres://old-alias/x")

	got, source, err := PostgresDSN()
	if err != nil || got != "postgres://old-alias/x" {
		t.Fatalf("deprecated alias should still work: got %q err %v", got, err)
	}
	if source != "environment variable VULNETIC_PG_DSN" {
		t.Fatalf("source should name the new var regardless of which one actually fired: got %q", source)
	}
}
