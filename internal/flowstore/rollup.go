package flowstore

// Tier 2 daily rollups (ROADMAP Phase 2). Before the detail tables are pruned
// (default 7 days), each COMPLETE day is aggregated into day-resolution rollup
// tables kept far longer (default 2 years). This is the "graceful degradation"
// step: instead of per-ASN detail vanishing at a cliff, you keep the daily top
// talkers/prefixes/ports/countries/proto per ASN — plus a per-IP daily total
// that survives even for IPs that never made an ASN top-N bucket.
//
// The rollup is idempotent: rolling a day first clears that day's rollup rows,
// so re-running (after a restart, downtime gap or a failure part-way) re-derives
// identical output. The writes are batched (storage.write_batch_rows) so the
// write lock is never held for long; the done-marker in flowstore_rollup_done is
// written last, so a day is only skipped once it was rolled completely. The
// whole scan window is checked each run so gaps are filled.

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"argus/internal/sqlite"
)

const (
	daySeconds = 86400
	// rollupMinWindowDays is the floor on how far back rollupDaily scans for
	// un-rolled days — enough to catch a multi-week downtime gap regardless of
	// how short the detail retention is.
	rollupMinWindowDays = 60
	// rollupMaxWindowDays caps the scan (and the initial backfill against a DB
	// that already holds a lot of detail). The done-marker makes re-scanning this
	// window cheap (mostly skips).
	rollupMaxWindowDays = 400
	// rollupGraceSeconds delays rolling a just-ended day so the 30-min detail
	// flush has time to persist its final bucket before the day is marked done.
	rollupGraceSeconds = 3600
)

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

	-- Explicit "day rolled" marker. Presence means the day was rolled (possibly
	-- to zero rows), so empty/quiet days are not re-scanned every tick and a day
	-- is never rolled twice even after its daily rows are pruned.
	CREATE TABLE IF NOT EXISTS flowstore_rollup_done (day INTEGER PRIMARY KEY);
	`)
	return err
}

// dayStart returns the UTC-midnight epoch for the day containing ts.
func dayStart(ts int64) int64 { return (ts / daySeconds) * daySeconds }

// rollupWindowDays scales the scan window to cover both a multi-week downtime
// gap (floor) and the detail retention (so no prunable day is ever outside the
// rollup window), capped so the initial backfill stays bounded.
func (s *Store) rollupWindowDays() int {
	w := s.limits.RetentionDays
	if w < 0 { // detail kept forever — still backfill a generous window
		w = rollupMaxWindowDays
	}
	if w < rollupMinWindowDays {
		w = rollupMinWindowDays
	}
	if w > rollupMaxWindowDays {
		w = rollupMaxWindowDays
	}
	return w
}

// rollupDaily rolls every settled day in the scan window that has not been
// rolled yet. A day is "settled" once it ended at least rollupGraceSeconds ago,
// so its final 30-min detail bucket has been flushed. The window is a fixed
// rollupWindowDays back (not tied to detail retention) so a downtime gap up to
// that many days is still caught before its detail is pruned. Runs before the
// detail prune, and at startup to catch up after downtime.
//
// It returns an error on the first day that fails to roll; the caller MUST skip
// the detail prune for that tick so an un-rolled day's detail is not deleted.
func (s *Store) rollupDaily() error {
	now := time.Now().UTC().Unix()
	oldest := dayStart(now) - int64(s.rollupWindowDays())*daySeconds

	for day := oldest; day+daySeconds <= now-rollupGraceSeconds; day += daySeconds {
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

// dayRolled reports whether a day was already rolled, via the explicit marker
// (set inside rollupOneDay's transaction) — reliable even for zero-row days.
func (s *Store) dayRolled(day int64) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM flowstore_rollup_done WHERE day = ?`, day).Scan(&one)
	switch err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}

// dailyTables are the Tier-2 rollup tables, all keyed by day first.
var dailyTables = []string{
	"flowstore_daily_ips", "flowstore_daily_prefixes", "flowstore_daily_ports",
	"flowstore_daily_country", "flowstore_daily_proto", "flowstore_daily_ip_totals",
}

// rollupOneDay rolls one day. A day is millions of rows (≈2.6M daily_ips +
// ip_totals on a busy AS), so it is NOT one transaction any more: the source
// detail is streamed through a plain read (a WAL snapshot, which does not
// block writers) and the rollup rows are written in WriteBatchRows-sized
// transactions. A single transaction held the write lock for ~1 minute and
// made every other writer fail with SQLITE_BUSY.
//
// Atomicity now comes from ordering instead: the day's rows are cleared first
// and the done-marker is written last, only after every batch committed. A
// crash or error part-way leaves no marker, so the next run clears the partial
// rows and rolls the day again. Requires WAL (reads and writes overlap on
// different pool connections).
func (s *Store) rollupOneDay(day int64) error {
	start, end := day, day+daySeconds
	batch := s.limits.WriteBatchRows

	// Idempotency: clear any partial/previous rollup for this day first.
	for _, t := range dailyTables {
		if _, err := sqlite.DeleteBatched(s.db, t, "day = ?", batch, day); err != nil {
			return fmt.Errorf("clear %s: %w", t, err)
		}
	}

	if err := rollIPs(s.db, batch, day, start, end, s.limits.TopIPs); err != nil {
		return fmt.Errorf("ips: %w", err)
	}
	if err := rollTopN(s.db, batch, day, start, end, s.limits.TopPrefixes,
		"flowstore_top_prefixes", "prefix", "flowstore_daily_prefixes"); err != nil {
		return fmt.Errorf("prefixes: %w", err)
	}
	if err := rollTopN(s.db, batch, day, start, end, s.limits.TopPorts,
		"flowstore_ports", "dst_port", "flowstore_daily_ports"); err != nil {
		return fmt.Errorf("ports: %w", err)
	}
	if err := rollTopN(s.db, batch, day, start, end, -1,
		"flowstore_country", "country", "flowstore_daily_country"); err != nil {
		return fmt.Errorf("country: %w", err)
	}
	if err := rollTopN(s.db, batch, day, start, end, -1,
		"flowstore_proto", "proto", "flowstore_daily_proto"); err != nil {
		return fmt.Errorf("proto: %w", err)
	}
	if err := rollIPTotals(s.db, batch, day, start, end); err != nil {
		return fmt.Errorf("ip totals: %w", err)
	}
	// Mark the day done last: absent marker ⇒ the day is (re-)rolled.
	_, err := s.db.Exec(`INSERT OR REPLACE INTO flowstore_rollup_done (day) VALUES (?)`, day)
	return err
}

// topN tracks the per-(asn, dir) rank while streaming rows ordered by
// asn, dir, SUM(bytes) DESC. limit < 0 keeps all.
type topN struct {
	limit  int
	asn    uint32
	dir    string
	n      int
	primed bool
}

// keep reports whether the next row of (asn, dir) is still inside the top-N.
func (t *topN) keep(asn uint32, dir string) bool {
	if !t.primed || asn != t.asn || dir != t.dir {
		t.asn, t.dir, t.n, t.primed = asn, dir, 0, true
	}
	if t.limit >= 0 && t.n >= t.limit {
		return false
	}
	t.n++
	return true
}

// rollIPs aggregates the 30-min top-IP rows for a day and keeps the top `limit`
// per (asn, dir) by bytes. limit < 0 keeps all.
//
// It groups by exactly the daily_ips primary key. country is not part of that
// key, and the same IP pair can carry two countries within a day (GeoIP update,
// or a flow seen before enrichment), so grouping by country too produced two
// rows per key and a UNIQUE failure that blocked the day — and the detail
// prune behind it — forever. MAX(country) picks one deterministically.
func rollIPs(db *sql.DB, batch int, day, start, end int64, limit int) error {
	rows, err := db.Query(`
		SELECT asn, dir, peer_ip, local_ip, proto, dst_port, MAX(country),
		       SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_ips
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, peer_ip, local_ip, proto, dst_port
		ORDER BY asn, dir, SUM(bytes) DESC`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	w := sqlite.NewBatchWriter(db, `
		INSERT INTO flowstore_daily_ips
			(day, asn, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, batch)
	rank := topN{limit: limit}
	for rows.Next() {
		var asn uint32
		var dir, peerIP, localIP, country string
		var proto, dstPort int
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &peerIP, &localIP, &proto, &dstPort, &country,
			&bytes, &packets, &flows); err != nil {
			return err
		}
		if !rank.keep(asn, dir) {
			continue // past the per-group top-N
		}
		if err := w.Add(day, asn, dir, peerIP, localIP, proto, dstPort, country,
			bytes, packets, flows); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// rollTopN rolls a single-key breakdown table (prefix/port/country/proto),
// keeping the top `limit` keys per (asn, dir) by bytes; limit < 0 keeps all
// (country/proto are naturally small).
func rollTopN(db *sql.DB, batch int, day, start, end int64, limit int, srcTable, keyCol, dstTable string) error {
	rows, err := db.Query(`
		SELECT asn, dir, `+keyCol+`, SUM(bytes), SUM(packets), SUM(flows)
		FROM `+srcTable+`
		WHERE ts >= ? AND ts < ?
		GROUP BY asn, dir, `+keyCol+`
		ORDER BY asn, dir, SUM(bytes) DESC`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	w := sqlite.NewBatchWriter(db, `
		INSERT INTO `+dstTable+` (day, asn, dir, `+keyCol+`, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, batch)
	rank := topN{limit: limit}
	for rows.Next() {
		var asn uint32
		var dir string
		var key interface{}
		var bytes, packets, flows int64
		if err := rows.Scan(&asn, &dir, &key, &bytes, &packets, &flows); err != nil {
			return err
		}
		if !rank.keep(asn, dir) {
			continue
		}
		if err := w.Add(day, asn, dir, key, bytes, packets, flows); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// rollIPTotals rolls per-IP daily totals across ALL ASNs (no top-N), so a quiet
// peer IP keeps a daily history row even if it never dominated an ASN bucket.
func rollIPTotals(db *sql.DB, batch int, day, start, end int64) error {
	rows, err := db.Query(`
		SELECT peer_ip, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_ips
		WHERE ts >= ? AND ts < ?
		GROUP BY peer_ip, dir`, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	w := sqlite.NewBatchWriter(db, `
		INSERT INTO flowstore_daily_ip_totals (day, peer_ip, dir, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?)`, batch)
	for rows.Next() {
		var peerIP, dir string
		var bytes, packets, flows int64
		if err := rows.Scan(&peerIP, &dir, &bytes, &packets, &flows); err != nil {
			return err
		}
		if err := w.Add(day, peerIP, dir, bytes, packets, flows); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// pruneDaily deletes daily rollup rows older than DailyRetentionDays. Negative
// retention keeps them forever. Done-markers are pruned separately, only once a
// day falls outside the scan window — so a day whose data is pruned (e.g. a
// short daily retention) is NOT re-rolled while still inside the window.
func (s *Store) pruneDaily() {
	today := dayStart(time.Now().UTC().Unix())

	// Marker prune: only for days older than the largest possible scan window,
	// so removing a marker can never cause a re-roll. Keeps the table bounded.
	markerCutoff := today - int64(rollupMaxWindowDays+1)*daySeconds
	if _, err := s.db.Exec(`DELETE FROM flowstore_rollup_done WHERE day < ?`, markerCutoff); err != nil {
		log.Printf("[flowstore] prune flowstore_rollup_done: %v", err)
	}

	retentionDays := s.limits.DailyRetentionDays
	if retentionDays < 0 {
		return // keep the rollup data forever
	}
	cutoff := today - int64(retentionDays)*daySeconds
	for _, t := range dailyTables {
		if _, err := sqlite.DeleteBatched(s.db, t, "day < ?", s.limits.WriteBatchRows, cutoff); err != nil {
			log.Printf("[flowstore] prune %s: %v", t, err)
		}
	}
}
