package api

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openIPProfileTestDB(t *testing.T) *sql.DB {
	t.Helper()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.sqlite")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE ip_profile (
			ip TEXT PRIMARY KEY,
			asn TEXT,
			asn_name TEXT,
			country TEXT,
			ptr TEXT,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			hits INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL
		)
	`); err != nil {
		t.Fatalf("create ip_profile: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE blackholes (
			prefix TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			rule TEXT,
			reason TEXT,
			asn TEXT,
			asn_name TEXT,
			country TEXT,
			ptr TEXT
		)
	`); err != nil {
		t.Fatalf("create blackholes: %v", err)
	}
	return db
}

func TestIPProfileUpsertAndLookupFresh(t *testing.T) {
	oldDB := DB
	t.Cleanup(func() { DB = oldDB })

	DB = openIPProfileTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := upsertIPProfile(&ipProfileRow{
		IP:      "203.0.113.10",
		ASN:     "64500",
		ASNName: "ExampleNet",
		Country: "US",
		PTR:     "host.example.test",
	}, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	row, fresh, err := lookupFreshIPProfile("203.0.113.10", now.Add(10*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !fresh {
		t.Fatalf("expected fresh row")
	}
	if row == nil || row.ASNName != "ExampleNet" {
		t.Fatalf("unexpected row: %+v", row)
	}
}

func TestCleanupIPProfileCache_RetentionAndCap(t *testing.T) {
	db := openIPProfileTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	insert := func(ip string, updated time.Time) {
		_, err := db.Exec(`
			INSERT INTO ip_profile (ip, asn, asn_name, country, ptr, first_seen, last_seen, hits, updated_at)
			VALUES (?, '', '', '', '', ?, ?, 1, ?)
		`, ip, updated.Format(time.RFC3339), updated.Format(time.RFC3339), updated.Format(time.RFC3339))
		if err != nil {
			t.Fatalf("insert %s: %v", ip, err)
		}
	}

	insert("203.0.113.1", now.Add(-48*time.Hour))
	insert("203.0.113.2", now.Add(-2*time.Hour))
	insert("203.0.113.3", now.Add(-1*time.Hour))

	cleanupIPProfileCache(db, now, 24*time.Hour, 1)

	var kept int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ip_profile`).Scan(&kept); err != nil {
		t.Fatalf("count: %v", err)
	}
	if kept != 1 {
		t.Fatalf("expected 1 row kept, got %d", kept)
	}
}

func TestFetchLatestBlackholeEvent_IPv4UsesSlash32(t *testing.T) {
	oldDB := DB
	t.Cleanup(func() { DB = oldDB })

	DB = openIPProfileTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(1 * time.Hour).Format(time.RFC3339)
	if _, err := DB.Exec(`
		INSERT INTO blackholes (prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "203.0.113.9/32", now.Format(time.RFC3339), expires, "v4-rule", "v4-reason", "64500", "ExampleNet", "US", "v4.example.test"); err != nil {
		t.Fatalf("insert blackhole ipv4: %v", err)
	}

	event, err := fetchLatestBlackholeEvent("203.0.113.9")
	if err != nil {
		t.Fatalf("fetchLatestBlackholeEvent ipv4: %v", err)
	}
	if event == nil {
		t.Fatalf("expected ipv4 event, got nil")
	}
	if got := event["prefix"]; got != "203.0.113.9/32" {
		t.Fatalf("expected prefix 203.0.113.9/32, got %v", got)
	}
}

func TestFetchLatestBlackholeEvent_IPv6UsesSlash128(t *testing.T) {
	oldDB := DB
	t.Cleanup(func() { DB = oldDB })

	DB = openIPProfileTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(1 * time.Hour).Format(time.RFC3339)
	if _, err := DB.Exec(`
		INSERT INTO blackholes (prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "2001:db8::1234/128", now.Format(time.RFC3339), expires, "v6-rule", "v6-reason", "64501", "ExampleV6Net", "US", "v6.example.test"); err != nil {
		t.Fatalf("insert blackhole ipv6: %v", err)
	}

	event, err := fetchLatestBlackholeEvent("2001:db8::1234")
	if err != nil {
		t.Fatalf("fetchLatestBlackholeEvent ipv6: %v", err)
	}
	if event == nil {
		t.Fatalf("expected ipv6 event, got nil")
	}
	if got := event["prefix"]; got != "2001:db8::1234/128" {
		t.Fatalf("expected prefix 2001:db8::1234/128, got %v", got)
	}
}
