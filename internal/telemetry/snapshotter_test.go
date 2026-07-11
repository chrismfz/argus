package telemetry

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openSnapDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "snap_test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := InitSchema(db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func insertSnap(t *testing.T, db *sql.DB, period string, createdAt int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO snapshots (period, ts_start, ts_end, created_at, note, data) VALUES (?, ?, ?, ?, '', '{}')`,
		period, createdAt-86400, createdAt, createdAt,
	); err != nil {
		t.Fatalf("insert %s: %v", period, err)
	}
}

func periodsLeft(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	rows, err := db.Query(`SELECT period, COUNT(*) FROM snapshots GROUP BY period`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[p] = n
	}
	return out
}

// TestPruneSnapshotsPeriodAware verifies that only old "daily" snapshots are
// removed; recent daily and every weekly/monthly/yearly/manual snapshot survive.
func TestPruneSnapshotsPeriodAware(t *testing.T) {
	db := openSnapDB(t)

	now := time.Now()
	oldTs := now.Add(-500 * 24 * time.Hour).Unix() // beyond a 400d retention
	recentTs := now.Add(-1 * 24 * time.Hour).Unix()

	insertSnap(t, db, "daily", oldTs)    // should be pruned
	insertSnap(t, db, "daily", recentTs) // should survive
	insertSnap(t, db, "weekly", oldTs)   // kept regardless of age
	insertSnap(t, db, "monthly", oldTs)  // kept
	insertSnap(t, db, "yearly", oldTs)   // kept
	insertSnap(t, db, "manual", oldTs)   // kept (explicit user intent)

	if err := PruneSnapshots(db, 400*24*time.Hour); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}

	left := periodsLeft(t, db)
	if left["daily"] != 1 {
		t.Fatalf("expected 1 surviving daily snapshot, got %d", left["daily"])
	}
	for _, p := range []string{"weekly", "monthly", "yearly", "manual"} {
		if left[p] != 1 {
			t.Fatalf("%s snapshot must be kept, got %d", p, left[p])
		}
	}
}

// TestPruneSnapshotsDisabled confirms retention <= 0 keeps everything.
func TestPruneSnapshotsDisabled(t *testing.T) {
	db := openSnapDB(t)
	insertSnap(t, db, "daily", time.Now().Add(-5000*24*time.Hour).Unix())
	if err := PruneSnapshots(db, 0); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if left := periodsLeft(t, db); left["daily"] != 1 {
		t.Fatalf("retention 0 must keep all, got %d daily", left["daily"])
	}
}
