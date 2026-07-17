package flowstore

// Tier 2 daily rollups (ROADMAP Phase 2). Before the detail tables are pruned
// (default 7 days), each COMPLETE day is aggregated into day-resolution rollup
// tables kept far longer (default 2 years). This is the "graceful degradation"
// step: instead of per-ASN detail vanishing at a cliff, you keep the daily top
// talkers/prefixes/ports/countries/proto per ASN — plus a per-IP daily total
// that survives even for IPs that never made an ASN top-N bucket.
//
// The rollup is idempotent: each day is rolled inside one transaction that first
// clears that day's rollup rows, so re-running (after a restart or downtime gap)
// re-derives identical output. A day is rolled only once — a cheap existence
// check on flowstore_daily_ips marks it done — but the whole detail-retention
// window is scanned each run so gaps are filled.

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

const daySeconds = 86400

func initRollupSchema(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS flowstore_daily_ips (
		day      INTEGER NOT NULL,
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
		PRIMARY KEY (day, asn, dir, peer_ip, local_ip, proto, dst_port)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdips_asn ON flowstore_daily_ips(asn, day DESC);
	CREATE INDEX IF NOT EXISTS idx_fsdips_ip  ON flowstore_daily_ips(peer_ip, day DESC);

	CREATE TABLE IF NOT EXISTS flowstore_daily_prefixes (
		day     INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		prefix  TEXT    NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, asn, dir, prefix)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdpfx_asn ON flowstore_daily_prefixes(asn, day DESC);

	CREATE TABLE IF NOT EXISTS flowstore_daily_ports (
		day      INTEGER NOT NULL,
		asn      INTEGER NOT NULL,
		dir      TEXT    NOT NULL,
		dst_port INTEGER NOT NULL,
		bytes    INTEGER NOT NULL DEFAULT 0,
		packets  INTEGER NOT NULL DEFAULT 0,
		flows    INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, asn, dir, dst_port)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdports_asn ON flowstore_daily_ports(asn, day DESC);

	CREATE TABLE IF NOT EXISTS flowstore_daily_country (
		day     INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		country TEXT    NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, asn, dir, country)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdcountry_asn ON flowstore_daily_country(asn, day DESC);

	CREATE TABLE IF NOT EXISTS flowstore_daily_proto (
		day     INTEGER NOT NULL,
		asn     INTEGER NOT NULL,
		dir     TEXT    NOT NULL,
		proto   INTEGER NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, asn, dir, proto)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdproto_asn ON flowstore_daily_proto(asn, day DESC);

	-- Per-IP daily totals, independent of ASN top-N: keeps a quiet IP's history
	-- even though it only ever appeared in a single top-N detail bucket.
	CREATE TABLE IF NOT EXISTS flowstore_daily_ip_totals (
		day     INTEGER NOT NULL,
		peer_ip TEXT    NOT NULL,
		dir     TEXT    NOT NULL,
		bytes   INTEGER NOT NULL DEFAULT 0,
		packets INTEGER NOT NULL DEFAULT 0,
		flows   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, peer_ip, dir)
	);
	CREATE INDEX IF NOT EXISTS idx_fsdiptot_ip ON flowstore_daily_ip_totals(peer_ip, day DESC);
	`)
	return err
}

// dayStart returns the UTC-midnight epoch for the day containing ts.
func dayStart(ts int64) int64 { return (ts / daySeconds) * daySeconds }

// rollupDue rolls every complete day still inside the detail-retention window
// that has not been rolled yet. "Complete" means the day has fully ended
// (day+86400 <= today's start), so its detail rows are final. Runs before the
// detail prune, and again at startup to catch up after downtime.
func (s *Store) rollupDaily() error {
	todayStart := dayStart(time.Now().UTC().Unix())

	// Oldest day whose detail still exists. Detail prune keeps RetentionDays;
	// a negative retention means "keep forever", so cap the scan window to a
	// sane bound to avoid an unbounded backfill.
	windowDays := s.limits.RetentionDays
	if windowDays < 0 || windowDays > 60 {
		windowDays = 60
	}
	oldest := todayStart - int64(windowDays)*daySeconds

	for day := oldest; day < todayStart; day += daySeconds {
		done, err := s.dayRolled(day)
		if err != nil {
			return err
		}
		if done {
			continue
		}
		if err := s.rollupOneDay(day); err != nil {
			return fmt.Errorf("rollup day %d: %w", day, err)
		}
	}
	return nil
}

// dayRolled reports whether a day already has rollup rows. Because each day is
// rolled inside a single transaction, presence is a reliable "fully done" mark.
func (s *Store) dayRolled(day int64) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM flowstore_daily_ips WHERE day = ? LIMIT 1`, day).Scan(&one)
	if err == sql.ErrNoRows {
		// No IP rows — but a day could legitimately have traffic without top IPs?
		// In practice every rolled day has IP rows; if a day truly had none, also
		// check ip_totals so we don't re-roll an empty day forever.
		err = s.db.QueryRow(`SELECT 1 FROM flowstore_daily_ip_totals WHERE day = ? LIMIT 1`, day).Scan(&one)
		if err == sql.ErrNoRows {
			return false, nil
		}
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) rollupOneDay(day int64) error {
	start, end := day, day+daySeconds

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Idempotency: clear any partial/previous rollup for this day first.
	for _, t := range []string{
		"flowstore_daily_ips", "flowstore_daily_prefixes", "flowstore_daily_ports",
		"flowstore_daily_country", "flowstore_daily_proto", "flowstore_daily_ip_totals",
	} {
		if _, err := tx.Exec(`DELETE FROM `+t+` WHERE day = ?`, day); err != nil {
			return err
		}
	}

	if err := rollIPs(tx, day, start, end, s.limits.TopIPs); err != nil {
		return err
	}
	if err := rollPrefixes(tx, day, start, end, s.limits.TopPrefixes); err != nil {
		return err
	}
	if err := rollPorts(tx, day, start, end, s.limits.TopPorts); err != nil {
		return err
	}
	if err := rollGroupAll(tx, day, start, end,
		"flowstore_country", "country", "flowstore_daily_country"); err != nil {
		return err
	}
	if err := rollGroupAll(tx, day, start, end,
		"flowstore_proto", "proto", "flowstore_daily_proto"); err != nil {
		return err
	}
	if err := rollIPTotals(tx, day, start, end); err != nil {
		return err
	}
	return tx.Commit()
}

// rollIPs aggregates the 30-min top-IP rows for a day and keeps the top `limit`
// per (asn, dir) by bytes. limit < 0 keeps all.
func rollIPs(tx *sql.Tx, day, start, end int64, limit int) error {
	rows, err := tx.Query(`
		SELECT asn, dir, peer_ip, local_ip, proto, dst_port, country,
		       SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_ips
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, peer_ip, local_ip, proto, dst_port, country
		ORDER BY asn, dir, SUM(bytes) DESC`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	ins, err := tx.Prepare(`
		INSERT INTO flowstore_daily_ips
			(day, asn, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	var curASN uint32
	var curDir string
	var n int
	first := true
	for rows.Next() {
		var asn uint32
		var dir, peerIP, localIP, country string
		var proto, dstPort int
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &peerIP, &localIP, &proto, &dstPort, &country,
			&bytes, &packets, &flows); err != nil {
			return err
		}
		if first || asn != curASN || dir != curDir {
			curASN, curDir, n, first = asn, dir, 0, false
		}
		if limit >= 0 && n >= limit {
			continue // past the per-group top-N
		}
		if _, err := ins.Exec(day, asn, dir, peerIP, localIP, proto, dstPort, country,
			bytes, packets, flows); err != nil {
			return err
		}
		n++
	}
	return rows.Err()
}

func rollPrefixes(tx *sql.Tx, day, start, end int64, limit int) error {
	rows, err := tx.Query(`
		SELECT asn, dir, prefix, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_prefixes
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, prefix
		ORDER BY asn, dir, SUM(bytes) DESC`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	ins, err := tx.Prepare(`
		INSERT INTO flowstore_daily_prefixes (day, asn, dir, prefix, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	var curASN uint32
	var curDir string
	var n int
	first := true
	for rows.Next() {
		var asn uint32
		var dir, prefix string
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &prefix, &bytes, &packets, &flows); err != nil {
			return err
		}
		if first || asn != curASN || dir != curDir {
			curASN, curDir, n, first = asn, dir, 0, false
		}
		if limit >= 0 && n >= limit {
			continue
		}
		if _, err := ins.Exec(day, asn, dir, prefix, bytes, packets, flows); err != nil {
			return err
		}
		n++
	}
	return rows.Err()
}

func rollPorts(tx *sql.Tx, day, start, end int64, limit int) error {
	rows, err := tx.Query(`
		SELECT asn, dir, dst_port, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_ports
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, dst_port
		ORDER BY asn, dir, SUM(bytes) DESC`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	ins, err := tx.Prepare(`
		INSERT INTO flowstore_daily_ports (day, asn, dir, dst_port, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	var curASN uint32
	var curDir string
	var n int
	first := true
	for rows.Next() {
		var asn uint32
		var dir string
		var dstPort int
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &dstPort, &bytes, &packets, &flows); err != nil {
			return err
		}
		if first || asn != curASN || dir != curDir {
			curASN, curDir, n, first = asn, dir, 0, false
		}
		if limit >= 0 && n >= limit {
			continue
		}
		if _, err := ins.Exec(day, asn, dir, dstPort, bytes, packets, flows); err != nil {
			return err
		}
		n++
	}
	return rows.Err()
}

// rollGroupAll rolls a single-key breakdown table (country/proto) keeping ALL
// groups — they are naturally small.
func rollGroupAll(tx *sql.Tx, day, start, end int64, srcTable, keyCol, dstTable string) error {
	rows, err := tx.Query(`
		SELECT asn, dir, `+keyCol+`, SUM(bytes), SUM(packets), SUM(flows)
		FROM `+srcTable+`
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, `+keyCol, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	ins, err := tx.Prepare(`
		INSERT INTO ` + dstTable + ` (day, asn, dir, ` + keyCol + `, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	for rows.Next() {
		var asn uint32
		var dir string
		var key interface{}
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &key, &bytes, &packets, &flows); err != nil {
			return err
		}
		if _, err := ins.Exec(day, asn, dir, key, bytes, packets, flows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// rollIPTotals rolls per-IP daily totals across ALL ASNs (no top-N), so a quiet
// peer IP keeps a daily history row even if it never dominated an ASN bucket.
func rollIPTotals(tx *sql.Tx, day, start, end int64) error {
	rows, err := tx.Query(`
		SELECT peer_ip, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_ips
		WHERE ts >= ? AND ts < ?
		GROUP BY peer_ip, dir`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	ins, err := tx.Prepare(`
		INSERT INTO flowstore_daily_ip_totals (day, peer_ip, dir, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	for rows.Next() {
		var peerIP, dir string
		var bytes, packets, flows int64
		if err := rows.Scan(&peerIP, &dir, &bytes, &packets, &flows); err != nil {
			return err
		}
		if _, err := ins.Exec(day, peerIP, dir, bytes, packets, flows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// pruneDaily deletes daily rollup rows older than DailyRetentionDays. Negative
// retention keeps them forever.
func (s *Store) pruneDaily() {
	retentionDays := s.limits.DailyRetentionDays
	if retentionDays < 0 {
		return
	}
	cutoff := dayStart(time.Now().UTC().Unix()) - int64(retentionDays)*daySeconds
	for _, t := range []string{
		"flowstore_daily_ips", "flowstore_daily_prefixes", "flowstore_daily_ports",
		"flowstore_daily_country", "flowstore_daily_proto", "flowstore_daily_ip_totals",
	} {
		if _, err := s.db.Exec(`DELETE FROM `+t+` WHERE day < ?`, cutoff); err != nil {
			log.Printf("[flowstore] prune %s: %v", t, err)
		}
	}
}
