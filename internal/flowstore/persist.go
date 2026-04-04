package flowstore

import (
	"database/sql"
	"log"
	"sort"
	"time"
)

// ── Schema ────────────────────────────────────────────────────────────────────

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
	-- 5-min resolution traffic timeline per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_timeline (
		ts       INTEGER NOT NULL,
		asn      INTEGER NOT NULL,
		asn_name TEXT    NOT NULL DEFAULT '',
		dir      TEXT    NOT NULL,
		bytes    INTEGER NOT NULL DEFAULT 0,
		packets  INTEGER NOT NULL DEFAULT 0,
		flows    INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir)
	);
	CREATE INDEX IF NOT EXISTS idx_fstl_asn ON flowstore_timeline(asn, ts DESC);

	-- Per-upstream-interface byte split within the timeline (same 5-min windows).
	CREATE TABLE IF NOT EXISTS flowstore_timeline_iface (
		ts    INTEGER NOT NULL,
		asn   INTEGER NOT NULL,
		dir   TEXT    NOT NULL,
		iface TEXT    NOT NULL,
		bytes INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, iface)
	);
	CREATE INDEX IF NOT EXISTS idx_fstli_asn ON flowstore_timeline_iface(asn, ts DESC);

	-- Hourly top-50 IP pairs per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_top_ips (
		ts       INTEGER NOT NULL,
		asn      INTEGER NOT NULL,
		dir      TEXT    NOT NULL,
		peer_ip  TEXT    NOT NULL,
		local_ip TEXT    NOT NULL,
		proto    INTEGER NOT NULL,
		dst_port INTEGER NOT NULL,
		country  TEXT    NOT NULL DEFAULT '',
		bytes    INTEGER NOT NULL DEFAULT 0,
		packets  INTEGER NOT NULL DEFAULT 0,
		flows    INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, peer_ip, local_ip, proto, dst_port)
	);
	CREATE INDEX IF NOT EXISTS idx_fstips_asn ON flowstore_top_ips(asn, ts DESC);

	-- Hourly top-20 BGP prefixes per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_top_prefixes (
		ts      INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		prefix  TEXT    NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, prefix)
	);
	CREATE INDEX IF NOT EXISTS idx_fspfx_asn ON flowstore_top_prefixes(asn, ts DESC);

	-- Hourly protocol breakdown per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_proto (
		ts      INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		proto   INTEGER NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, proto)
	);
	CREATE INDEX IF NOT EXISTS idx_fsproto_asn ON flowstore_proto(asn, ts DESC);

	-- Hourly country breakdown per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_country (
		ts      INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		country TEXT    NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, country)
	);
	CREATE INDEX IF NOT EXISTS idx_fscountry_asn ON flowstore_country(asn, ts DESC);

	-- Hourly top-10 destination ports per ASN + direction.
	CREATE TABLE IF NOT EXISTS flowstore_ports (
		ts       INTEGER NOT NULL,
		asn      INTEGER NOT NULL,
		dir      TEXT    NOT NULL,
		dst_port INTEGER NOT NULL,
		bytes    INTEGER NOT NULL DEFAULT 0,
		packets  INTEGER NOT NULL DEFAULT 0,
		flows    INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir, dst_port)
	);
	CREATE INDEX IF NOT EXISTS idx_fsports_asn ON flowstore_ports(asn, ts DESC);

	-- Hourly TCP flag counters per ASN + direction (TCP flows only).
	CREATE TABLE IF NOT EXISTS flowstore_tcp_flags (
		ts        INTEGER NOT NULL,
		asn       INTEGER NOT NULL,
		dir       TEXT    NOT NULL,
		tcp_flows INTEGER NOT NULL DEFAULT 0,
		syn_count INTEGER NOT NULL DEFAULT 0,
		ack_count INTEGER NOT NULL DEFAULT 0,
		rst_count INTEGER NOT NULL DEFAULT 0,
		fin_count INTEGER NOT NULL DEFAULT 0,
		psh_count INTEGER NOT NULL DEFAULT 0,
		urg_count INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, asn, dir)
	);
	CREATE INDEX IF NOT EXISTS idx_fsflags_asn ON flowstore_tcp_flags(asn, ts DESC);

	-- Permanent per-ASN metadata (first seen, last seen, lifetime bytes).
	CREATE TABLE IF NOT EXISTS flowstore_asn_meta (
		asn        INTEGER PRIMARY KEY,
		asn_name   TEXT    NOT NULL DEFAULT '',
		first_seen INTEGER NOT NULL DEFAULT 0,
		last_seen  INTEGER NOT NULL DEFAULT 0,
		total_in   INTEGER NOT NULL DEFAULT 0,
		total_out  INTEGER NOT NULL DEFAULT 0
	);
	`)
	return err
}

// ── flush5m ───────────────────────────────────────────────────────────────────

// flush5m drains the timeline accumulator and writes it to SQLite.
// Also writes ASN meta deltas. Called every 5 minutes.
func (s *Store) flush5m() error {
	s.mu.Lock()
	tl     := s.tl
	deltas := s.drainMetaDeltas()
	s.tl    = make(map[tlKey]*tlVal)
	s.mu.Unlock()

	if len(tl) == 0 && len(deltas) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Timeline rows.
	tlStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_timeline
			(ts, asn, asn_name, dir, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer tlStmt.Close()

	// Interface-split rows.
	ifStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_timeline_iface
			(ts, asn, dir, iface, bytes)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer ifStmt.Close()

	for k, v := range tl {
		if _, err := tlStmt.Exec(
			k.ts, k.asn, v.asnName, k.dir,
			v.bytes, v.packets, v.flows,
		); err != nil {
			log.Printf("[flowstore] flush5m timeline row: %v", err)
		}
		for iface, b := range v.ifaces {
			if _, err := ifStmt.Exec(k.ts, k.asn, k.dir, iface, b); err != nil {
				log.Printf("[flowstore] flush5m iface row: %v", err)
			}
		}
	}

	// ASN meta — upsert with delta bytes using SQLite's ON CONFLICT.
	metaStmt, err := tx.Prepare(`
		INSERT INTO flowstore_asn_meta
			(asn, asn_name, first_seen, last_seen, total_in, total_out)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(asn) DO UPDATE SET
			asn_name   = CASE WHEN excluded.asn_name != '' THEN excluded.asn_name
			                  ELSE asn_name END,
			first_seen = CASE WHEN first_seen = 0
			                  THEN excluded.first_seen
			                  ELSE MIN(first_seen, excluded.first_seen) END,
			last_seen  = MAX(last_seen, excluded.last_seen),
			total_in   = total_in  + excluded.total_in,
			total_out  = total_out + excluded.total_out
	`)
	if err != nil {
		return err
	}
	defer metaStmt.Close()

	for asn, d := range deltas {
		if _, err := metaStmt.Exec(
			asn, d.asnName, d.firstSeen, d.lastSeen, d.deltaIn, d.deltaOut,
		); err != nil {
			log.Printf("[flowstore] flush5m meta row: %v", err)
		}
	}

	return tx.Commit()
}

// drainMetaDeltas snapshots pending byte deltas from s.meta and resets them.
// Must be called with s.mu held.
func (s *Store) drainMetaDeltas() map[uint32]metaDelta {
	if len(s.meta) == 0 {
		return nil
	}
	out := make(map[uint32]metaDelta, len(s.meta))
	for asn, m := range s.meta {
		if m.pendingIn == 0 && m.pendingOut == 0 {
			continue
		}
		out[asn] = metaDelta{
			asnName:   m.asnName,
			firstSeen: m.firstSeen,
			lastSeen:  m.lastSeen,
			deltaIn:   m.pendingIn,
			deltaOut:  m.pendingOut,
		}
		m.pendingIn  = 0
		m.pendingOut = 0
	}
	return out
}

// ── flushHourly ───────────────────────────────────────────────────────────────

// flushHourly drains the hourly accumulators and writes top-N records to
// the detail tables. Called every hour.
func (s *Store) flushHourly() error {
	s.mu.Lock()
	hours   := s.hours
	s.hours  = make(map[hourKey]*hourAccum)
	s.mu.Unlock()

	if len(hours) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for hk, ha := range hours {
		if err := writeTopIPs(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly ips asn=%d: %v", hk.asn, err)
		}
		if err := writeTopPrefixes(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly pfx asn=%d: %v", hk.asn, err)
		}
		if err := writeProto(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly proto asn=%d: %v", hk.asn, err)
		}
		if err := writeCountry(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly country asn=%d: %v", hk.asn, err)
		}
		if err := writePorts(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly ports asn=%d: %v", hk.asn, err)
		}
		if err := writeTCPFlags(tx, hk, ha); err != nil {
			log.Printf("[flowstore] flushHourly flags asn=%d: %v", hk.asn, err)
		}
	}

	return tx.Commit()
}

// ── Per-table writers ─────────────────────────────────────────────────────────

type ipEntry struct {
	k ipKey
	v *ipCounter
}

func writeTopIPs(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if len(ha.ips) == 0 {
		return nil
	}
	entries := make([]ipEntry, 0, len(ha.ips))
	for k, v := range ha.ips {
		entries = append(entries, ipEntry{k, v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].v.bytes > entries[j].v.bytes
	})
	if len(entries) > topIPs {
		entries = entries[:topIPs]
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_top_ips
			(ts, asn, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(
			hk.ts, hk.asn, hk.dir,
			e.k.peerIP, e.k.localIP, e.k.proto, e.k.dstPort,
			e.v.country,
			e.v.bytes, e.v.packets, e.v.flows,
		); err != nil {
			return err
		}
	}
	return nil
}

type pfxEntry struct {
	pfx string
	c   *counter
}

func writeTopPrefixes(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if len(ha.pfx) == 0 {
		return nil
	}
	entries := make([]pfxEntry, 0, len(ha.pfx))
	for pfx, c := range ha.pfx {
		entries = append(entries, pfxEntry{pfx, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].c.bytes > entries[j].c.bytes
	})
	if len(entries) > topPfx {
		entries = entries[:topPfx]
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_top_prefixes
			(ts, asn, dir, prefix, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(
			hk.ts, hk.asn, hk.dir,
			e.pfx, e.c.bytes, e.c.packets, e.c.flows,
		); err != nil {
			return err
		}
	}
	return nil
}

func writeProto(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if len(ha.proto) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_proto
			(ts, asn, dir, proto, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for proto, c := range ha.proto {
		if _, err := stmt.Exec(
			hk.ts, hk.asn, hk.dir,
			proto, c.bytes, c.packets, c.flows,
		); err != nil {
			return err
		}
	}
	return nil
}

func writeCountry(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if len(ha.country) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_country
			(ts, asn, dir, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for country, c := range ha.country {
		if _, err := stmt.Exec(
			hk.ts, hk.asn, hk.dir,
			country, c.bytes, c.packets, c.flows,
		); err != nil {
			return err
		}
	}
	return nil
}

type portEntry struct {
	port uint16
	c    *counter
}

func writePorts(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if len(ha.ports) == 0 {
		return nil
	}
	entries := make([]portEntry, 0, len(ha.ports))
	for port, c := range ha.ports {
		entries = append(entries, portEntry{port, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].c.bytes > entries[j].c.bytes
	})
	if len(entries) > topPorts {
		entries = entries[:topPorts]
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO flowstore_ports
			(ts, asn, dir, dst_port, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(
			hk.ts, hk.asn, hk.dir,
			e.port, e.c.bytes, e.c.packets, e.c.flows,
		); err != nil {
			return err
		}
	}
	return nil
}

func writeTCPFlags(tx *sql.Tx, hk hourKey, ha *hourAccum) error {
	if ha.tcpFlows == 0 {
		return nil
	}
	_, err := tx.Exec(`
		INSERT OR REPLACE INTO flowstore_tcp_flags
			(ts, asn, dir, tcp_flows, syn_count, ack_count, rst_count, fin_count, psh_count, urg_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		hk.ts, hk.asn, hk.dir,
		ha.tcpFlows,
		ha.synCount, ha.ackCount, ha.rstCount,
		ha.finCount, ha.pshCount, ha.urgCount,
	)
	return err
}

// ── Prune ─────────────────────────────────────────────────────────────────────

// prune deletes rows older than `retention` days from all time-series tables.
// flowstore_asn_meta is intentionally kept forever.
func (s *Store) prune() error {
	cutoff := time.Now().Unix() - int64(retention)*86400
	tables := []string{
		"flowstore_timeline",
		"flowstore_timeline_iface",
		"flowstore_top_ips",
		"flowstore_top_prefixes",
		"flowstore_proto",
		"flowstore_country",
		"flowstore_ports",
		"flowstore_tcp_flags",
	}
	for _, t := range tables {
		if _, err := s.db.Exec(`DELETE FROM `+t+` WHERE ts < ?`, cutoff); err != nil {
			log.Printf("[flowstore] prune %s: %v", t, err)
		}
	}
	return nil
}

// ── Warmup ────────────────────────────────────────────────────────────────────

// warmupMeta loads flowstore_asn_meta into the in-memory meta map on startup.
func (s *Store) warmupMeta() error {
	rows, err := s.db.Query(`
		SELECT asn, asn_name, first_seen, last_seen
		FROM flowstore_asn_meta
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var asn uint32
		var name string
		var first, last int64
		if err := rows.Scan(&asn, &name, &first, &last); err != nil {
			continue
		}
		s.meta[asn] = &metaAccum{
			asnName:   name,
			firstSeen: first,
			lastSeen:  last,
		}
	}
	return rows.Err()
}
