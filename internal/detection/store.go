package detection

import (
	"argus/internal/bgp"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

type DetectionStore interface {
	IncrementCount(rule, ip string) (int, error)
	GetCount(rule, ip string) (int, error)
}

//
// --- MemoryStore (παλιό logic, in-memory fallback) ---
//

type MemoryStore struct {
	mu     sync.RWMutex
	counts map[string]map[string]int // rule → ip → count
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		counts: make(map[string]map[string]int),
	}
}

func (m *MemoryStore) IncrementCount(rule, ip string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.counts[rule] == nil {
		m.counts[rule] = make(map[string]int)
	}
	m.counts[rule][ip]++
	return m.counts[rule][ip], nil
}

func (m *MemoryStore) GetCount(rule, ip string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.counts[rule] == nil {
		return 0, nil
	}
	return m.counts[rule][ip], nil
}

//
// --- SQLiteStore (νέο persistent logic) ---
//

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// DB exposes the underlying handle for callers that need raw SQL access
// (e.g. the blackhole history audit log).
func (s *SQLiteStore) DB() *sql.DB { return s.db }

func (s *SQLiteStore) IncrementCount(rule, ip string) (int, error) {

	now := time.Now().Format(time.RFC3339)
	// Single-statement upsert + return to shorten lock duration.
	row := s.db.QueryRow(`
		INSERT INTO detections (ip, rule, count, first_seen, last_seen)
		VALUES (?, ?, 1, ?, ?)
		ON CONFLICT(ip, rule) DO UPDATE SET
			count = detections.count + 1,
			last_seen = excluded.last_seen
		RETURNING count
	`, ip, rule, now, now)

	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("sqlite increment failed: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) GetCount(rule, ip string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT count FROM detections WHERE ip = ? AND rule = ?`, ip, rule).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("sqlite get failed: %w", err)
	}
	return count, nil
}

// RestoreActiveBlackholes φορτώνει όλα τα ενεργά prefixes από SQLite και τα ανακοινώνει ξανά
func RestoreActiveBlackholes(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT prefix FROM blackholes
		WHERE expires_at > datetime('now')
	`)
	if err != nil {
		return fmt.Errorf("failed to query active blackholes: %w", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err != nil {
			log.Printf("[WARN] Failed to scan prefix: %v", err)
			continue
		}

		// Default announce χωρίς έξτρα community / next-hop (θα οριστεί από config)
		err = bgp.AnnouncePrefix(prefix, "", nil, []uint32{})
		if err != nil {
			log.Printf("[WARN] Failed to re-announce prefix %s: %v", prefix, err)
		} else {
			log.Printf("[RESTORE] Re-announced prefix %s from SQLite", prefix)
			count++
		}
	}

	if count > 0 {
		log.Printf("[RESTORE] Total re-announced blackholes: %d", count)
	}
	return nil
}

func (s *SQLiteStore) InsertBlackhole(
	prefix, timestamp, expires, rule, reason, asn, asnName, country, ptr string,
) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO blackholes (prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, prefix, timestamp, expires, rule, reason, asn, asnName, country, ptr)
	return err
}

// InsertRiskEvent persists one risk.log line to SQLite.
// Called from afterTickPrintInteresting right after logRiskLine.
// Non-fatal on error — risk.log is always the authoritative record.
func (s *SQLiteStore) InsertRiskEvent(
	ts int64,
	src string,
	fused, ifScore, hbosNorm, ehbosNorm float64,
	mu, thr float64,
	shape, exampleDst string,
	exCount int,
	asn uint32,
	asnName, cc, ptr string,
) {
	_, err := s.db.Exec(`
		INSERT INTO risk_events
			(ts, src, fused, if_score, hbos_norm, ehbos_norm, mu, thr,
			 shape, example_dst, ex_count, asn, asn_name, cc, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, src, fused, ifScore, hbosNorm, ehbosNorm, mu, thr,
		shape, exampleDst, exCount, asn, asnName, cc, ptr,
	)
	if err != nil {
		log.Printf("[WARN] risk_events insert failed src=%s: %v", src, err)
	}
}

// PurgeOldRiskEvents enforces retention on the risk_events table: it deletes
// rows older than maxAge, then trims to at most maxRows (FIFO by id). risk_events
// is the highest-frequency detection table (one row per "interesting" anomaly per
// tick) and, unlike blackhole_events, had no hard row cap — so a burst (e.g. a
// DDoS lighting up thousands of sources) could pile on rows faster than the age
// window pruned them. The row cap is the backstop that keeps the table (and the
// SQLite file it shares) bounded. Wire into the same cleanup ticker as
// CleanupExpiredBlackholes in main.go.
//
// maxAge <= 0 disables age pruning (keep forever); maxRows <= 0 disables the cap.
func PurgeOldRiskEvents(db *sql.DB, maxAge time.Duration, maxRows int) error {
	if db == nil {
		return nil
	}
	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge).Unix()
		res, err := db.Exec(`DELETE FROM risk_events WHERE ts < ?`, cutoff)
		if err != nil {
			return fmt.Errorf("purge risk_events by age: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[risk_events] purged %d rows older than %s", n, maxAge)
		}
	}
	if maxRows > 0 {
		res, err := db.Exec(`
			DELETE FROM risk_events
			WHERE id IN (
				SELECT id FROM risk_events
				ORDER BY id DESC
				LIMIT -1 OFFSET ?
			)`, maxRows)
		if err != nil {
			return fmt.Errorf("purge risk_events by count: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[risk_events] purged %d rows over cap of %d", n, maxRows)
		}
	}
	return nil
}
