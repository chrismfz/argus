package detection

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestPruneDetections exercises the real DELETE ... datetime('now', ?) path to
// confirm the bound modifier works and old rows (by last_seen) are removed while
// recent ones survive.
func TestPruneDetections(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "det_test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE detections (
		ip TEXT NOT NULL, rule TEXT NOT NULL, last_seen TEXT,
		PRIMARY KEY (ip, rule))`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	insert := func(ip string, lastSeen time.Time) {
		if _, err := db.Exec(
			`INSERT INTO detections (ip, rule, last_seen) VALUES (?, 'r', ?)`,
			ip, lastSeen.Format(time.RFC3339),
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert("1.1.1.1", time.Now().Add(-100*24*time.Hour)) // stale → pruned
	insert("2.2.2.2", time.Now().Add(-1*24*time.Hour))   // recent → kept

	if err := PruneDetections(db, 90*24*time.Hour); err != nil {
		t.Fatalf("PruneDetections: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM detections`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 surviving row, got %d", count)
	}
	var ip string
	if err := db.QueryRow(`SELECT ip FROM detections`).Scan(&ip); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ip != "2.2.2.2" {
		t.Fatalf("wrong row survived: got %s, want the recent 2.2.2.2", ip)
	}

	// retention <= 0 disables pruning.
	insert("3.3.3.3", time.Now().Add(-9999*24*time.Hour))
	if err := PruneDetections(db, 0); err != nil {
		t.Fatalf("PruneDetections(0): %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM detections`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("retention 0 must keep all, got %d", count)
	}
}
