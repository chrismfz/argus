package detection

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"argus/internal/bgp"
	"argus/internal/sqlite"

	_ "modernc.org/sqlite"
)

func openBlackholeTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// CleanupExpiredBlackholes queues blackhole_events rows for a background
	// writer, which races the test's own queries: WAL + busy_timeout make them
	// wait instead of failing with SQLITE_BUSY (as production's DSN does).
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "bh.db")+
		"?mode=rwc&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := sqlite.InitSQLiteSchema(db); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func insertBlackholeRow(t *testing.T, db *sql.DB, prefix, expires, rule string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO blackholes (prefix, timestamp, expires_at, rule) VALUES (?, ?, ?, ?)`,
		prefix, time.Now().Format(time.RFC3339), expires, rule,
	); err != nil {
		t.Fatalf("insert %s: %v", prefix, err)
	}
}

// The way HandleBlackhole and the API write expires_at: RFC3339 with a local
// (non-UTC) offset. A fixed +02:00 zone keeps the test independent of TZ.
var athens = time.FixedZone("EET", 2*3600)

func TestCleanupExpiredBlackholesHonoursOffset(t *testing.T) {
	db := openBlackholeTestDB(t)
	now := time.Now()

	// Expired an hour ago. The old string compare against datetime('now') kept
	// this row (and its route) until the UTC date rolled over.
	insertBlackholeRow(t, db, "198.51.100.1/32", now.Add(-time.Hour).In(athens).Format(time.RFC3339), "r")
	insertBlackholeRow(t, db, "198.51.100.2/32", now.Add(-time.Minute).UTC().Format(time.RFC3339), "r")
	insertBlackholeRow(t, db, "198.51.100.3/32", now.Add(time.Hour).In(athens).Format(time.RFC3339), "r")
	insertBlackholeRow(t, db, "198.51.100.4/32", "9999-12-31T00:00:00Z", "r") // permanent marker
	insertBlackholeRow(t, db, "198.51.100.5/32", "not-a-date", "r")           // unparseable: left alone

	if err := CleanupExpiredBlackholes(db); err != nil {
		t.Fatalf("CleanupExpiredBlackholes: %v", err)
	}

	rows, err := db.Query(`SELECT prefix FROM blackholes ORDER BY prefix`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var left []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("scan: %v", err)
		}
		left = append(left, p)
	}
	want := []string{"198.51.100.3/32", "198.51.100.4/32", "198.51.100.5/32"}
	if !reflect.DeepEqual(left, want) {
		t.Fatalf("surviving blackholes = %v; want %v", left, want)
	}

	// Let the async writer land both "expired" events before the temp dir (and
	// the DB in it) is removed, or it logs a disk I/O error after the test.
	waitForEvents(t, db, BHEventExpired, 2)
}

type announceCall struct {
	nextHop     string
	communities []string
}

func TestRestoreActiveBlackholesUsesRuleParams(t *testing.T) {
	db := openBlackholeTestDB(t)
	now := time.Now()

	prevLocal := bgp.LocalBGPAddress
	bgp.LocalBGPAddress = "203.0.113.10"
	t.Cleanup(func() { bgp.LocalBGPAddress = prevLocal })

	rules := []DetectionRule{{
		Name:                 "slow_horizontal_scan",
		BlackholeNextHop:     "192.0.2.1",
		BlackholeCommunities: []string{"65001:666"},
	}}

	active := now.Add(2 * time.Hour).In(athens).Format(time.RFC3339)
	insertBlackholeRow(t, db, "198.51.100.10/32", active, "slow_horizontal_scan")
	insertBlackholeRow(t, db, "198.51.100.11/32", active, "(api)") // no such rule
	insertBlackholeRow(t, db, "198.51.100.12/32", "9999-12-31T00:00:00Z", "slow_horizontal_scan")
	// Expired by the clock but "later" than datetime('now') as a string: must
	// not be resurrected.
	insertBlackholeRow(t, db, "198.51.100.13/32", now.Add(-time.Hour).In(athens).Format(time.RFC3339), "slow_horizontal_scan")

	got := map[string]announceCall{}
	fake := func(prefix, nextHop string, communities []string, asPath []uint32) error {
		got[prefix] = announceCall{nextHop, communities}
		return nil
	}
	if err := restoreActiveBlackholes(db, rules, fake); err != nil {
		t.Fatalf("restore: %v", err)
	}

	ruleCall := announceCall{"192.0.2.1", []string{"65001:666"}}
	want := map[string]announceCall{
		"198.51.100.10/32": ruleCall,
		"198.51.100.12/32": ruleCall,
		// Unknown rule falls back to the same defaults HandleBlackhole uses —
		// crucially still with the blackhole community.
		"198.51.100.11/32": {"203.0.113.10", []string{"65001:666"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("announces = %+v; want %+v", got, want)
	}
}

func TestBlackholeAnnounceParamsDefaults(t *testing.T) {
	prevLocal := bgp.LocalBGPAddress
	bgp.LocalBGPAddress = ""
	t.Cleanup(func() { bgp.LocalBGPAddress = prevLocal })

	nh, coms := blackholeAnnounceParams(DetectionRule{Name: "x"})
	if nh != "192.0.2.1" || !reflect.DeepEqual(coms, []string{"65001:666"}) {
		t.Fatalf("defaults = %s %v", nh, coms)
	}
}

func waitForEvents(t *testing.T, db *sql.DB, event string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM blackhole_events WHERE event = ?`, event).Scan(&n); err != nil {
			t.Fatalf("count events: %v", err)
		}
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("blackhole_events %q: %d rows after 5s; want %d", event, n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
