package flowstore

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openRollupDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "rollup_test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	if err := initRollupSchema(db); err != nil {
		t.Fatalf("initRollupSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func insTopIP(t *testing.T, db *sql.DB, ts int64, asn uint32, dir, peerIP string, port int, bytes int64) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO flowstore_top_ips
		(ts, asn, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, '10.0.0.1', 6, ?, 'US', ?, 1, 1)`,
		ts, asn, dir, peerIP, port, bytes)
	if err != nil {
		t.Fatalf("insert top_ip: %v", err)
	}
}

func TestRollupAggregatesAndCaps(t *testing.T) {
	db := openRollupDB(t)
	s := &Store{db: db, limits: Settings{TopIPs: 50}.withDefaults()}

	// Use yesterday so rollupDaily treats it as a complete day.
	day := dayStart(time.Now().UTC().Unix()) - daySeconds
	b0 := day + 0*1800     // first 30-min bucket
	b1 := day + 1*1800     // second bucket (same day)
	other := day + 12*3600 // noon, same day

	// ASN 100: 60 distinct peer IPs (past the top-50 cut). Give ip #0 traffic
	// in TWO buckets so we can check the daily SUM.
	for i := 0; i < 60; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		insTopIP(t, db, b0, 100, "in", ip, 443, int64(1000+i)) // higher i = more bytes
	}
	insTopIP(t, db, b1, 100, "in", "203.0.113.0", 443, 500) // ip .0 again, different bucket
	// ASN 200: a couple of IPs.
	insTopIP(t, db, other, 200, "out", "198.51.100.7", 80, 9999)

	if err := s.rollupDaily(); err != nil {
		t.Fatalf("rollupDaily: %v", err)
	}

	// ── top-N cut per (asn, dir): ASN 100 must keep exactly 50 IP rows. ──
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM flowstore_daily_ips WHERE day=? AND asn=100 AND dir='in'`, day).Scan(&n)
	if n != 50 {
		t.Fatalf("expected top-50 IPs for ASN 100, got %d", n)
	}

	// ── per-IP daily SUM across buckets: ip .0 = 1000 + 500 = 1500. ──
	// (ip .0 has the LOWEST per-bucket bytes so it may fall outside the ASN
	// top-50, but the per-IP totals table keeps ALL IPs regardless.)
	var total int64
	err := db.QueryRow(`SELECT bytes FROM flowstore_daily_ip_totals
		WHERE day=? AND peer_ip='203.0.113.0' AND dir='in'`, day).Scan(&total)
	if err != nil {
		t.Fatalf("ip_totals for .0: %v", err)
	}
	if total != 1500 {
		t.Fatalf("per-IP daily total for .0 = %d, want 1500 (1000+500)", total)
	}

	// ── per-IP totals keeps ALL 60 IPs (no top-N). ──
	db.QueryRow(`SELECT COUNT(*) FROM flowstore_daily_ip_totals WHERE day=? AND dir='in'`, day).Scan(&n)
	if n != 60 {
		t.Fatalf("per-IP totals should keep all 60 IPs, got %d", n)
	}

	// ── ASN 200 rolled independently. ──
	db.QueryRow(`SELECT COUNT(*) FROM flowstore_daily_ips WHERE day=? AND asn=200`, day).Scan(&n)
	if n != 1 {
		t.Fatalf("ASN 200 should have 1 daily IP row, got %d", n)
	}
}

func TestRollupIdempotent(t *testing.T) {
	db := openRollupDB(t)
	s := &Store{db: db, limits: DefaultSettings()}
	day := dayStart(time.Now().UTC().Unix()) - daySeconds
	insTopIP(t, db, day+1800, 100, "in", "203.0.113.5", 443, 1000)

	if err := s.rollupDaily(); err != nil {
		t.Fatalf("rollup 1: %v", err)
	}
	// Second run must be a no-op (day already rolled) — not double the totals.
	if err := s.rollupDaily(); err != nil {
		t.Fatalf("rollup 2: %v", err)
	}
	var total int64
	db.QueryRow(`SELECT bytes FROM flowstore_daily_ip_totals WHERE day=? AND peer_ip='203.0.113.5'`, day).Scan(&total)
	if total != 1000 {
		t.Fatalf("idempotency broken: total=%d, want 1000 (rolled twice?)", total)
	}
	// And rollupOneDay directly is also idempotent (DELETE-then-insert).
	if err := s.rollupOneDay(day); err != nil {
		t.Fatalf("rollupOneDay: %v", err)
	}
	db.QueryRow(`SELECT bytes FROM flowstore_daily_ip_totals WHERE day=? AND peer_ip='203.0.113.5'`, day).Scan(&total)
	if total != 1000 {
		t.Fatalf("rollupOneDay not idempotent: total=%d", total)
	}
}

func TestRollupSkipsIncompleteToday(t *testing.T) {
	db := openRollupDB(t)
	s := &Store{db: db, limits: DefaultSettings()}
	today := dayStart(time.Now().UTC().Unix())
	insTopIP(t, db, today+60, 100, "in", "203.0.113.9", 443, 1000) // today, not complete

	if err := s.rollupDaily(); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM flowstore_daily_ips WHERE day=?`, today).Scan(&n)
	if n != 0 {
		t.Fatalf("today's (incomplete) day must not be rolled, got %d rows", n)
	}
}

func TestPruneDaily(t *testing.T) {
	db := openRollupDB(t)
	s := &Store{db: db, limits: Settings{DailyRetentionDays: 30}.withDefaults()}

	today := dayStart(time.Now().UTC().Unix())
	oldDay := today - 40*daySeconds  // past 30d retention
	freshDay := today - 5*daySeconds // within retention
	for _, d := range []int64{oldDay, freshDay} {
		_, err := db.Exec(`INSERT INTO flowstore_daily_ip_totals (day, peer_ip, dir, bytes, packets, flows)
			VALUES (?, '203.0.113.1', 'in', 1, 1, 1)`, d)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	s.pruneDaily()

	var days []int64
	rows, _ := db.Query(`SELECT day FROM flowstore_daily_ip_totals ORDER BY day`)
	defer rows.Close()
	for rows.Next() {
		var d int64
		rows.Scan(&d)
		days = append(days, d)
	}
	if len(days) != 1 || days[0] != freshDay {
		t.Fatalf("pruneDaily kept wrong rows: %v (want just %d)", days, freshDay)
	}

	// Negative retention keeps everything.
	s2 := &Store{db: db, limits: Settings{DailyRetentionDays: -1}.withDefaults()}
	_, _ = db.Exec(`INSERT INTO flowstore_daily_ip_totals (day, peer_ip, dir, bytes, packets, flows)
		VALUES (?, '203.0.113.2', 'in', 1, 1, 1)`, oldDay)
	s2.pruneDaily()
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM flowstore_daily_ip_totals`).Scan(&cnt)
	if cnt != 2 {
		t.Fatalf("negative retention must keep all, got %d rows", cnt)
	}
}
