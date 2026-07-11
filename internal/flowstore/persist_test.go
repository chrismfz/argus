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

func countTimeline(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM flowstore_timeline`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestPruneDropsOldRows verifies retention: timeline rows older than `retention`
// days are deleted, recent ones survive.
func TestPruneDropsOldRows(t *testing.T) {
	db := openTestDB(t)
	s := &Store{db: db}

	now := time.Now().Unix()
	old := now - int64(retention+1)*86400 // just past the retention window
	recent := now - 3600                  // an hour ago

	insert := func(ts int64, dir string) {
		if _, err := db.Exec(
			`INSERT INTO flowstore_timeline (ts, asn, dir, bytes) VALUES (?, ?, ?, ?)`,
			ts, 65000, dir, 1000,
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert(old, "in")
	insert(recent, "in")

	if got := countTimeline(t, db); got != 2 {
		t.Fatalf("precondition: expected 2 rows, got %d", got)
	}

	if err := s.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if got := countTimeline(t, db); got != 1 {
		t.Fatalf("after prune: expected 1 surviving row, got %d", got)
	}

	var survivingTs int64
	if err := db.QueryRow(`SELECT ts FROM flowstore_timeline`).Scan(&survivingTs); err != nil {
		t.Fatalf("scan surviving: %v", err)
	}
	if survivingTs != recent {
		t.Fatalf("wrong row survived: got ts=%d, want the recent ts=%d", survivingTs, recent)
	}
}
