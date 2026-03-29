package telemetry

import (
	"database/sql"
	"log"
	"time"
)

// ── Schema ────────────────────────────────────────────────────────────────────

// InitRingSchema creates the telemetry_buckets table (throughput ring).
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

// InitASNRingSchema creates the telemetry_asn_buckets table (per-ASN per-minute).
func InitASNRingSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS telemetry_asn_buckets (
			ts        INTEGER NOT NULL,
			asn       INTEGER NOT NULL,
			name      TEXT    NOT NULL DEFAULT '',
			bytes_in  INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			flows_in  INTEGER NOT NULL DEFAULT 0,
			flows_out INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ts, asn)
		);
		CREATE INDEX IF NOT EXISTS idx_tasnbuckets_ts  ON telemetry_asn_buckets(ts DESC);
		CREATE INDEX IF NOT EXISTS idx_tasnbuckets_asn ON telemetry_asn_buckets(asn, ts DESC);
	`)
	return err
}

// InitIfaceRingSchema creates the telemetry_iface_buckets table (per-interface per-minute).
func InitIfaceRingSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS telemetry_iface_buckets (
			ts        INTEGER NOT NULL,
			iface_idx INTEGER NOT NULL,
			name      TEXT    NOT NULL DEFAULT '',
			bytes_in  INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			flows_in  INTEGER NOT NULL DEFAULT 0,
			flows_out INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ts, iface_idx)
		);
		CREATE INDEX IF NOT EXISTS idx_tifacebuckets_ts ON telemetry_iface_buckets(ts DESC);
	`)
	return err
}

// ── Throughput ring ───────────────────────────────────────────────────────────

// PersistRing writes all non-zero ring buckets to SQLite.
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
			b.BytesIn, b.BytesOut, b.FlowsIn, b.FlowsOut, b.PktsIn, b.PktsOut,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WarmupRingFromDB restores throughput ring buckets from SQLite on startup.
func WarmupRingFromDB(db *sql.DB) (int, error) {
	if Global == nil {
		return 0, nil
	}
	cutoff := (time.Now().Unix()/60)*60 - int64(RingSize-1)*60
	rows, err := db.Query(`
		SELECT ts, bytes_in, bytes_out, flows_in, flows_out, pkts_in, pkts_out
		FROM telemetry_buckets WHERE ts >= ? ORDER BY ts ASC
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
		if err := rows.Scan(&b.Ts, &b.BytesIn, &b.BytesOut, &b.FlowsIn, &b.FlowsOut, &b.PktsIn, &b.PktsOut); err != nil {
			continue
		}
		slot := int((b.Ts / 60) % RingSize)
		Global.ring[slot] = b
		loaded++
	}
	return loaded, rows.Err()
}

// ── ASN ring ──────────────────────────────────────────────────────────────────

// PersistASNRing writes all asnRing buckets to SQLite.
func PersistASNRing(db *sql.DB) error {
	if Global == nil {
		return nil
	}
	Global.mu.RLock()
	// Snapshot the ring under read lock so ingest isn't blocked long
	type asnRow struct {
		ts                         int64
		asn                        uint32
		name                       string
		bytesIn, bytesOut          uint64
		flowsIn, flowsOut          uint64
	}
	var rows []asnRow
	for slot := 0; slot < RingSize; slot++ {
		slotTs := Global.ring[slot].Ts
		if slotTs == 0 {
			continue
		}
		for asn, c := range Global.asnRing[slot] {
			if c.bytesIn == 0 && c.bytesOut == 0 {
				continue
			}
			rows = append(rows, asnRow{
				ts: slotTs, asn: asn, name: c.name,
				bytesIn: c.bytesIn, bytesOut: c.bytesOut,
				flowsIn: c.flowsIn, flowsOut: c.flowsOut,
			})
		}
	}
	Global.mu.RUnlock()

	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO telemetry_asn_buckets
			(ts, asn, name, bytes_in, bytes_out, flows_in, flows_out)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.ts, r.asn, r.name, r.bytesIn, r.bytesOut, r.flowsIn, r.flowsOut); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WarmupASNRingFromDB restores the last 24h of asnRing from SQLite on startup.
func WarmupASNRingFromDB(db *sql.DB) (int, error) {
	if Global == nil {
		return 0, nil
	}
	cutoff := (time.Now().Unix()/60)*60 - int64(RingSize-1)*60
	dbRows, err := db.Query(`
		SELECT ts, asn, name, bytes_in, bytes_out, flows_in, flows_out
		FROM telemetry_asn_buckets WHERE ts >= ? ORDER BY ts ASC
	`, cutoff)
	if err != nil {
		return 0, err
	}
	defer dbRows.Close()

	type asnRow struct {
		ts, asn                    uint64
		name                       string
		bytesIn, bytesOut          uint64
		flowsIn, flowsOut          uint64
	}
	var buf []asnRow
	for dbRows.Next() {
		var r asnRow
		if err := dbRows.Scan(&r.ts, &r.asn, &r.name, &r.bytesIn, &r.bytesOut, &r.flowsIn, &r.flowsOut); err != nil {
			continue
		}
		buf = append(buf, r)
	}
	if err := dbRows.Err(); err != nil {
		return 0, err
	}

	loaded := 0
	Global.mu.Lock()
	defer Global.mu.Unlock()
	for _, r := range buf {
		slot := int((r.ts / 60) % uint64(RingSize))
		// Only restore if the slot timestamp matches — don't overwrite live data
		if Global.ring[slot].Ts != int64(r.ts) {
			continue
		}
		am := Global.asnRing[slot]
		if am == nil {
			am = make(map[uint32]*asnMinCount)
			Global.asnRing[slot] = am
		}
		c, ok := am[uint32(r.asn)]
		if !ok {
			c = &asnMinCount{name: r.name}
			am[uint32(r.asn)] = c
		}
		c.bytesIn += r.bytesIn
		c.bytesOut += r.bytesOut
		c.flowsIn += r.flowsIn
		c.flowsOut += r.flowsOut
		if c.name == "" && r.name != "" {
			c.name = r.name
		}
		loaded++
	}
	return loaded, nil
}

// ── Interface ring ────────────────────────────────────────────────────────────

// PersistIfaceRing writes all ifaceRing buckets to SQLite.
func PersistIfaceRing(db *sql.DB) error {
	if Global == nil {
		return nil
	}
	Global.mu.RLock()
	type ifaceRow struct {
		ts                         int64
		idx                        uint32
		name                       string
		bytesIn, bytesOut          uint64
		flowsIn, flowsOut          uint64
	}
	var rows []ifaceRow
	for slot := 0; slot < RingSize; slot++ {
		slotTs := Global.ring[slot].Ts
		if slotTs == 0 {
			continue
		}
		for idx, ic := range Global.ifaceRing[slot] {
			if ic.bytesIn == 0 && ic.bytesOut == 0 {
				continue
			}
			rows = append(rows, ifaceRow{
				ts: slotTs, idx: idx, name: ic.name,
				bytesIn: ic.bytesIn, bytesOut: ic.bytesOut,
				flowsIn: ic.flowsIn, flowsOut: ic.flowsOut,
			})
		}
	}
	Global.mu.RUnlock()

	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO telemetry_iface_buckets
			(ts, iface_idx, name, bytes_in, bytes_out, flows_in, flows_out)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.ts, r.idx, r.name, r.bytesIn, r.bytesOut, r.flowsIn, r.flowsOut); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WarmupIfaceRingFromDB restores the last 24h of ifaceRing from SQLite on startup.
func WarmupIfaceRingFromDB(db *sql.DB) (int, error) {
	if Global == nil {
		return 0, nil
	}
	cutoff := (time.Now().Unix()/60)*60 - int64(RingSize-1)*60
	dbRows, err := db.Query(`
		SELECT ts, iface_idx, name, bytes_in, bytes_out, flows_in, flows_out
		FROM telemetry_iface_buckets WHERE ts >= ? ORDER BY ts ASC
	`, cutoff)
	if err != nil {
		return 0, err
	}
	defer dbRows.Close()

	type ifaceRow struct {
		ts, idx                    uint64
		name                       string
		bytesIn, bytesOut          uint64
		flowsIn, flowsOut          uint64
	}
	var buf []ifaceRow
	for dbRows.Next() {
		var r ifaceRow
		if err := dbRows.Scan(&r.ts, &r.idx, &r.name, &r.bytesIn, &r.bytesOut, &r.flowsIn, &r.flowsOut); err != nil {
			continue
		}
		buf = append(buf, r)
	}
	if err := dbRows.Err(); err != nil {
		return 0, err
	}

	loaded := 0
	Global.mu.Lock()
	defer Global.mu.Unlock()
	for _, r := range buf {
		slot := int((r.ts / 60) % uint64(RingSize))
		if Global.ring[slot].Ts != int64(r.ts) {
			continue
		}
		im := Global.ifaceRing[slot]
		if im == nil {
			im = make(map[uint32]*ifaceMinCount)
			Global.ifaceRing[slot] = im
		}
		c, ok := im[uint32(r.idx)]
		if !ok {
			c = &ifaceMinCount{name: r.name}
			im[uint32(r.idx)] = c
		}
		c.bytesIn += r.bytesIn
		c.bytesOut += r.bytesOut
		c.flowsIn += r.flowsIn
		c.flowsOut += r.flowsOut
		if c.name == "" && r.name != "" {
			c.name = r.name
		}
		loaded++
	}
	return loaded, nil
}

// ── Prune ─────────────────────────────────────────────────────────────────────

// PruneOldBuckets deletes rows older than retentionDays from all three tables.
func PruneOldBuckets(db *sql.DB, retentionDays int) error {
	cutoff := time.Now().Unix() - int64(retentionDays)*86400
	for _, table := range []string{
		"telemetry_buckets",
		"telemetry_asn_buckets",
		"telemetry_iface_buckets",
	} {
		if _, err := db.Exec(`DELETE FROM `+table+` WHERE ts < ?`, cutoff); err != nil {
			log.Printf("[telemetry] prune %s failed: %v", table, err)
		}
	}
	return nil
}
