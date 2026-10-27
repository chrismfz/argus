package telemetry

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openRingDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "ring.db")+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, f := range []func(*sql.DB) error{InitRingSchema, InitASNRingSchema, InitIfaceRingSchema} {
		if err := f(db); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return db
}

// fillMinute puts one minute of traffic into the global ring, as Ingest would.
func fillMinute(ts int64, bytes uint64) {
	slot := int((ts / 60) % RingSize)
	Global.ring[slot] = MinuteBucket{Ts: ts, BytesIn: bytes, FlowsIn: 1}
	Global.asnRing[slot] = map[uint32]*asnMinCount{64500: {name: "TEST", bytesIn: bytes, flowsIn: 1}}
	Global.ifaceRing[slot] = map[uint32]*ifaceMinCount{3: {name: "sfp2", bytesIn: bytes, flowsIn: 1}}
}

func tsSet(t *testing.T, db *sql.DB, table string) map[int64]bool {
	t.Helper()
	rows, err := db.Query(`SELECT ts FROM ` + table)
	if err != nil {
		t.Fatalf("query %s: %v", table, err)
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[ts] = true
	}
	return out
}

// TestPersistSinceWritesOnlyNewMinutes covers the incremental flush: with a
// watermark only the minutes at/after it are (re)written, and since=0 still
// writes the whole ring (first flush after startup).
func TestPersistSinceWritesOnlyNewMinutes(t *testing.T) {
	prev := Global
	t.Cleanup(func() { Global = prev })
	Init(65000, "me", nil, nil)

	now := minEpoch(time.Now())
	old, mark, cur := now-30*60, now-5*60, now
	fillMinute(old, 100)
	fillMinute(mark, 200)
	fillMinute(cur, 300)

	persistAll := func(db *sql.DB, since int64) {
		t.Helper()
		if err := PersistRing(db, since); err != nil {
			t.Fatalf("PersistRing: %v", err)
		}
		if err := PersistASNRing(db, since); err != nil {
			t.Fatalf("PersistASNRing: %v", err)
		}
		if err := PersistIfaceRing(db, since); err != nil {
			t.Fatalf("PersistIfaceRing: %v", err)
		}
	}

	db := openRingDB(t)
	persistAll(db, mark)
	for _, table := range []string{"telemetry_buckets", "telemetry_asn_buckets", "telemetry_iface_buckets"} {
		got := tsSet(t, db, table)
		if len(got) != 2 || !got[mark] || !got[cur] || got[old] {
			t.Fatalf("%s with since=mark: got minutes %v; want only %d and %d", table, got, mark, cur)
		}
	}

	full := openRingDB(t)
	persistAll(full, 0)
	for _, table := range []string{"telemetry_buckets", "telemetry_asn_buckets", "telemetry_iface_buckets"} {
		if got := tsSet(t, full, table); len(got) != 3 {
			t.Fatalf("%s with since=0: got %d minutes; want the whole ring (3)", table, len(got))
		}
	}

	// A re-flush of the watermark minute must update, not duplicate.
	fillMinute(mark, 999)
	persistAll(db, mark)
	var bytesIn uint64
	var n int
	if err := db.QueryRow(`SELECT COUNT(*), MAX(bytes_in) FROM telemetry_asn_buckets WHERE ts = ?`, mark).Scan(&n, &bytesIn); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 || bytesIn != 999 {
		t.Fatalf("watermark minute after re-flush: rows=%d bytes_in=%d; want 1 row with 999", n, bytesIn)
	}
}
