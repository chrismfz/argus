package flowstore

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "flowstore_test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestPruneSplitRetention verifies the independent retention windows: detail
// tables prune at RetentionDays while the 5-min timeline keeps rows for the
// longer TimelineRetentionDays.
func TestPruneSplitRetention(t *testing.T) {
	db := openTestDB(t)
	s := &Store{db: db, limits: Settings{
		RetentionDays:         7,
		TimelineRetentionDays: 30,
	}.withDefaults()}

	now := time.Now().Unix()
	day := int64(86400)

	insTimeline := func(ts int64) {
		if _, err := db.Exec(
			`INSERT INTO flowstore_timeline (ts, asn, dir, bytes) VALUES (?, 65000, 'in', 1)`, ts,
		); err != nil {
			t.Fatalf("insert timeline: %v", err)
		}
	}
	insDetail := func(ts int64) {
		if _, err := db.Exec(
			`INSERT INTO flowstore_ports (ts, asn, dir, dst_port, bytes) VALUES (?, 65000, 'in', 443, 1)`, ts,
		); err != nil {
			t.Fatalf("insert detail: %v", err)
		}
	}

	insTimeline(now - 31*day) // past timeline retention → pruned
	insTimeline(now - 10*day) // past detail retention, inside timeline → KEPT
	insTimeline(now - day)    // recent → kept
	insDetail(now - 10*day)   // past detail retention → pruned
	insDetail(now - day)      // recent → kept

	if err := s.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if got := countRows(t, db, "flowstore_timeline"); got != 2 {
		t.Fatalf("timeline: expected 2 surviving rows (10d-old must be kept), got %d", got)
	}
	if got := countRows(t, db, "flowstore_ports"); got != 1 {
		t.Fatalf("detail: expected 1 surviving row, got %d", got)
	}
}

// TestPruneKeepForever verifies negative retention disables pruning entirely.
func TestPruneKeepForever(t *testing.T) {
	db := openTestDB(t)
	s := &Store{db: db, limits: Settings{
		RetentionDays:         -1,
		TimelineRetentionDays: -1,
	}.withDefaults()}

	old := time.Now().Unix() - 400*86400
	if _, err := db.Exec(`INSERT INTO flowstore_timeline (ts, asn, dir, bytes) VALUES (?, 65000, 'in', 1)`, old); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO flowstore_ports (ts, asn, dir, dst_port, bytes) VALUES (?, 65000, 'in', 443, 1)`, old); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := s.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if countRows(t, db, "flowstore_timeline")+countRows(t, db, "flowstore_ports") != 2 {
		t.Fatal("negative retention must keep all rows")
	}
}

// TestSettingsWithDefaults confirms zero → default and negative passes through.
func TestSettingsWithDefaults(t *testing.T) {
	got := Settings{}.withDefaults()
	if got != DefaultSettings() {
		t.Fatalf("zero Settings must resolve to defaults, got %+v", got)
	}
	neg := Settings{TopIPs: -1, RetentionDays: -1}.withDefaults()
	if neg.TopIPs != -1 || neg.RetentionDays != -1 {
		t.Fatalf("negative values must pass through, got %+v", neg)
	}
	if neg.TopPorts != 10 || neg.TimelineRetentionDays != 30 {
		t.Fatalf("unset fields must still default, got %+v", neg)
	}
}
