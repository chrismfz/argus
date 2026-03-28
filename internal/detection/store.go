package detection

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
	"log"
	"argus/internal/bgp"
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
