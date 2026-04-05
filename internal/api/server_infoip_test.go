package api

import (
	"argus/internal/config"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBuildASPathHops_UsesTransitMapThenMetaThenFallback(t *testing.T) {
	oldCfg := config.AppConfig
	oldDB := DB
	t.Cleanup(func() {
		config.AppConfig = oldCfg
		DB = oldDB
	})

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.sqlite")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE flowstore_asn_meta (
			asn       INTEGER PRIMARY KEY,
			asn_name  TEXT NOT NULL DEFAULT '',
			first_seen INTEGER NOT NULL DEFAULT 0,
			last_seen  INTEGER NOT NULL DEFAULT 0,
			total_in   INTEGER NOT NULL DEFAULT 0,
			total_out  INTEGER NOT NULL DEFAULT 0
		)
	`); err != nil {
		t.Fatalf("create meta table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO flowstore_asn_meta (asn, asn_name) VALUES (64510, 'MetaCarrier')`); err != nil {
		t.Fatalf("insert meta row: %v", err)
	}
	DB = db

	config.AppConfig = &config.Config{}
	config.AppConfig.Pathfinder.TransitASNMap = map[uint32]string{
		64500: "TransitOne",
	}

	hops := buildASPathHops([]string{"64500", "64510", "64520"})
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}

	if got := hops[0]["asn_name"]; got != "TransitOne" {
		t.Fatalf("hop 0 asn_name = %q, want TransitOne", got)
	}
	if got := hops[1]["asn_name"]; got != "MetaCarrier" {
		t.Fatalf("hop 1 asn_name = %q, want MetaCarrier", got)
	}
	if got := hops[2]["asn_name"]; got != "AS64520" {
		t.Fatalf("hop 2 asn_name = %q, want AS64520", got)
	}
	for i, hop := range hops {
		if got := hop["country"]; got != "unsupported" {
			t.Fatalf("hop %d country = %q, want unsupported", i, got)
		}
	}
}

func TestResolveASNLabel_InvalidValue(t *testing.T) {
	oldCfg := config.AppConfig
	oldDB := DB
	t.Cleanup(func() {
		config.AppConfig = oldCfg
		DB = oldDB
	})

	config.AppConfig = &config.Config{}
	DB = nil

	if got := resolveASNLabel("not-a-number"); got != "ASnot-a-number" {
		t.Fatalf("invalid ASN fallback = %q", got)
	}
}
