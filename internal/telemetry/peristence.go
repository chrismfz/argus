package telemetry

import (
	"database/sql"
//	"log"
	"time"
)

// InitRingSchema creates the telemetry_buckets table.
// One row per minute-aligned epoch. Safe to call on every startup.
func InitRingSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS telemetry_buckets (
			ts        INTEGER PRIMARY KEY,
			bytes_in  INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			flows_in  INTEGER NOT NULL DEFAULT 0,
			flows_out INTEGER NOT NULL DEFAULT 0,
			pkts_in   INTEGER NOT NULL DEFAULT 0,
			pkts_out  INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_tbuckets_ts ON telemetry_buckets(ts DESC);
	`)
	return err
}

// PersistRing writes all non-zero ring buckets from the last 24h to SQLite.
// Uses INSERT OR REPLACE so it's safe to call repeatedly.
func PersistRing(db *sql.DB) error {
	if Global == nil {
		return nil
	}
	buckets := Global.QueryTimeSeries(RingSize)
	if len(buckets) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO telemetry_buckets
			(ts, bytes_in, bytes_out, flows_in, flows_out, pkts_in, pkts_out)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, b := range buckets {
		if b.Ts == 0 {
			continue
		}
		if _, err := stmt.Exec(b.Ts,
			b.BytesIn, b.BytesOut,
			b.FlowsIn, b.FlowsOut,
			b.PktsIn, b.PktsOut,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WarmupRingFromDB restores ring buckets from SQLite on startup.
// Only buckets within the last 24h are loaded — stale data is ignored.
// Call this after Init() and before the flow pipeline starts.
func WarmupRingFromDB(db *sql.DB) (int, error) {
	if Global == nil {
		return 0, nil
	}
	cutoff := (time.Now().Unix()/60)*60 - int64(RingSize-1)*60
	rows, err := db.Query(`
		SELECT ts, bytes_in, bytes_out, flows_in, flows_out, pkts_in, pkts_out
		FROM telemetry_buckets
		WHERE ts >= ?
		ORDER BY ts ASC
	`, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	loaded := 0
	Global.mu.Lock()
	defer Global.mu.Unlock()

	for rows.Next() {
		var b MinuteBucket
		if err := rows.Scan(&b.Ts,
			&b.BytesIn, &b.BytesOut,
			&b.FlowsIn, &b.FlowsOut,
			&b.PktsIn, &b.PktsOut,
		); err != nil {
			continue
		}
		slot := int((b.Ts / 60) % RingSize)
		Global.ring[slot] = b
		loaded++
	}
	return loaded, rows.Err()
}

// PruneOldBuckets deletes buckets older than retentionDays. Call periodically.
func PruneOldBuckets(db *sql.DB, retentionDays int) error {
	cutoff := time.Now().Unix() - int64(retentionDays)*86400
	_, err := db.Exec(`DELETE FROM telemetry_buckets WHERE ts < ?`, cutoff)
	return err
}
