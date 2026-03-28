package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// ── Schema ────────────────────────────────────────────────────────────────────

// InitSchema creates the snapshots table and indexes inside the existing SQLite
// database (same file used by detections / blackholes).
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS snapshots (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			period     TEXT    NOT NULL,
			ts_start   INTEGER NOT NULL,
			ts_end     INTEGER NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			note       TEXT    NOT NULL DEFAULT '',
			data       TEXT    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_snap_period  ON snapshots(period, ts_start);
		CREATE INDEX IF NOT EXISTS idx_snap_created ON snapshots(created_at DESC);
	`)
	return err
}

// ── Persistence ───────────────────────────────────────────────────────────────

// SaveSnapshot writes one snapshot row to SQLite and returns its row ID.
func SaveSnapshot(db *sql.DB, period string, tsStart, tsEnd int64, note string, data SnapshotData) (int64, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}
	res, err := db.Exec(
		`INSERT INTO snapshots (period, ts_start, ts_end, note, data) VALUES (?, ?, ?, ?, ?)`,
		period, tsStart, tsEnd, note, string(b),
	)
	if err != nil {
		return 0, fmt.Errorf("insert: %w", err)
	}
	return res.LastInsertId()
}

// TakeManualSnapshot creates a "manual" snapshot right now with an optional note.
// Useful before/after peering changes, upgrades, etc.
func TakeManualSnapshot(db *sql.DB, note string) (int64, error) {
	if Global == nil {
		return 0, fmt.Errorf("aggregator not initialised")
	}
	now := time.Now()
	data := Global.BuildSnapshot(1440)
	return SaveSnapshot(db, "manual", now.Add(-24*time.Hour).Unix(), now.Unix(), note, data)
}

// ── Query types ───────────────────────────────────────────────────────────────

// SnapshotMeta holds the header fields of a snapshot row (no heavy data blob).
type SnapshotMeta struct {
	ID        int64  `json:"id"`
	Period    string `json:"period"`
	TsStart   int64  `json:"ts_start"`
	TsEnd     int64  `json:"ts_end"`
	CreatedAt int64  `json:"created_at"`
	Note      string `json:"note"`
}

// ASNHistoryEntry is one data point in a historical ASN comparison.
type ASNHistoryEntry struct {
	SnapshotID int64  `json:"snapshot_id"`
	Period     string `json:"period"`
	Label      string `json:"label"`
	TsStart    int64  `json:"ts_start"`
	Note       string `json:"note"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	FlowsIn    uint64 `json:"flows_in"`
	FlowsOut   uint64 `json:"flows_out"`
}

// ── Retrieval ─────────────────────────────────────────────────────────────────

// ListSnapshots returns metadata for all snapshots, newest first.
func ListSnapshots(db *sql.DB) ([]SnapshotMeta, error) {
	rows, err := db.Query(
		`SELECT id, period, ts_start, ts_end, created_at, note
		 FROM snapshots ORDER BY ts_start DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SnapshotMeta
	for rows.Next() {
		var m SnapshotMeta
		if err := rows.Scan(&m.ID, &m.Period, &m.TsStart, &m.TsEnd, &m.CreatedAt, &m.Note); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetSnapshot retrieves both the metadata and the full data blob for one snapshot.
func GetSnapshot(db *sql.DB, id int64) (*SnapshotData, *SnapshotMeta, error) {
	row := db.QueryRow(
		`SELECT id, period, ts_start, ts_end, created_at, note, data
		 FROM snapshots WHERE id = ?`, id)
	var meta SnapshotMeta
	var dataStr string
	if err := row.Scan(&meta.ID, &meta.Period, &meta.TsStart, &meta.TsEnd,
		&meta.CreatedAt, &meta.Note, &dataStr); err != nil {
		return nil, nil, err
	}
	var data SnapshotData
	if err := json.Unmarshal([]byte(dataStr), &data); err != nil {
		return nil, nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &data, &meta, nil
}

// GetASNHistory returns per-snapshot stats for a given ASN.
// It returns the most recent snapshot of each period type, plus all manual
// snapshots — giving the caller "today / 1 week ago / 1 month ago / 1 year ago"
// rows out of the box.
func GetASNHistory(db *sql.DB, asn uint32) ([]ASNHistoryEntry, error) {
	// Fetch at most the 200 most recent snapshots (metadata + data).
	// For a year of daily + weekly + monthly + yearly + occasional manual this is ~430 rows max.
	rows, err := db.Query(
		`SELECT id, period, ts_start, note, data
		 FROM snapshots
		 ORDER BY ts_start DESC
		 LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Track the most recent snapshot seen per period type so we can deduplicate
	// to one row per period (daily → yesterday, weekly → last week, etc.)
	seenPeriod := make(map[string]bool)

	var out []ASNHistoryEntry
	for rows.Next() {
		var id int64
		var period string
		var tsStart int64
		var note, dataStr string
		if err := rows.Scan(&id, &period, &tsStart, &note, &dataStr); err != nil {
			continue
		}

		// For automatic snapshots, keep only the most recent of each period type.
		// Manual snapshots are always included (each is distinct).
		if period != "manual" {
			if seenPeriod[period] {
				continue
			}
			seenPeriod[period] = true
		}

		var data SnapshotData
		if err := json.Unmarshal([]byte(dataStr), &data); err != nil {
			continue
		}

		entry := ASNHistoryEntry{
			SnapshotID: id,
			Period:     period,
			Label:      periodLabel(period, tsStart),
			TsStart:    tsStart,
			Note:       note,
		}
		for _, a := range data.TopASNIn {
			if a.ASN == asn {
				entry.BytesIn = a.BytesIn
				entry.FlowsIn = a.FlowsIn
				break
			}
		}
		for _, a := range data.TopASNOut {
			if a.ASN == asn {
				entry.BytesOut = a.BytesOut
				entry.FlowsOut = a.FlowsOut
				break
			}
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func periodLabel(period string, ts int64) string {
	t := time.Unix(ts, 0)
	switch period {
	case "daily":
		return t.Format("2006-01-02")
	case "weekly":
		return "week of " + t.Format("2006-01-02")
	case "monthly":
		return t.Format("2006-01")
	case "yearly":
		return t.Format("2006")
	case "manual":
		return "manual " + t.Format("2006-01-02 15:04")
	default:
		return period + " " + t.Format("2006-01-02")
	}
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

// StartScheduler launches the background goroutine that takes automatic
// snapshots. It checks every minute whether a snapshot is due.
//
//	daily   — at 00:00 local time every day
//	weekly  — at 00:00 on Sunday
//	monthly — at 00:00 on the 1st of each month
//	yearly  — at 00:00 on Jan 1st
func StartScheduler(ctx context.Context, db *sql.DB) {
	if db == nil {
		log.Print("[telemetry] scheduler: no DB, snapshots disabled")
		return
	}
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		// On startup, load the timestamps of the last snapshots we already have
		// so that a restart doesn't immediately re-fire them.
		lastSeen := loadLastSeen(db)

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				checkAndTake(db, now, lastSeen)
			}
		}
	}()
	log.Print("[telemetry] snapshot scheduler started")

// ── Ring persistence — flush every 5 minutes ──────────────────────────────
go func() {
    t := time.NewTicker(5 * time.Minute)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            // Final flush on shutdown
            if err := PersistRing(db); err != nil {
                log.Printf("[telemetry] final ring flush failed: %v", err)
            }
            return
        case <-t.C:
            if err := PersistRing(db); err != nil {
                log.Printf("[telemetry] ring persist failed: %v", err)
            }
        }
    }
}()

// ── Daily prune — keep last 30 days (configurable) ───────────────────────
go func() {
    t := time.NewTicker(24 * time.Hour)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            if err := PruneOldBuckets(db, 30); err != nil {
                log.Printf("[telemetry] prune failed: %v", err)
            }
        }
    }
}()

}

// lastSeen tracks when we last took a snapshot of each period type.
type lastSeenMap map[string]time.Time

func loadLastSeen(db *sql.DB) lastSeenMap {
	m := lastSeenMap{}
	rows, err := db.Query(
		`SELECT period, MAX(ts_end) FROM snapshots GROUP BY period`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var period string
		var tsEnd int64
		if rows.Scan(&period, &tsEnd) == nil {
			m[period] = time.Unix(tsEnd, 0)
		}
	}
	return m
}

func midnight(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func checkAndTake(db *sql.DB, now time.Time, last lastSeenMap) {
	mn := midnight(now)
	// Only act in the first minute after midnight.
	if now.Before(mn) || now.After(mn.Add(time.Minute)) {
		return
	}

	type schedEntry struct {
		period    string
		condition bool
	}
	entries := []schedEntry{
		{"daily", true},
		{"weekly", now.Weekday() == time.Sunday},
		{"monthly", now.Day() == 1},
		{"yearly", now.Month() == time.January && now.Day() == 1},
	}

	for _, e := range entries {
		if !e.condition {
			continue
		}
		if t, ok := last[e.period]; ok && !t.Before(mn) {
			continue // already taken today
		}
		takeSnapshot(db, e.period, now)
		last[e.period] = now
		if e.period == "daily" {
			// Reset accumulated maps after the daily snapshot is safely stored.
			if Global != nil {
				Global.ResetAccumulators()
			}
		}
	}
}

func takeSnapshot(db *sql.DB, period string, now time.Time) {
	if Global == nil {
		return
	}
	start := now.Add(-24 * time.Hour)
	if period == "weekly" {
		start = now.Add(-7 * 24 * time.Hour)
	} else if period == "monthly" {
		start = now.Add(-30 * 24 * time.Hour)
	} else if period == "yearly" {
		start = now.Add(-365 * 24 * time.Hour)
	}

	data := Global.BuildSnapshot(1440)
	id, err := SaveSnapshot(db, period, start.Unix(), now.Unix(), "", data)
	if err != nil {
		log.Printf("[telemetry] %s snapshot FAILED: %v", period, err)
		return
	}
	log.Printf("[telemetry] %s snapshot saved id=%d asns=%d/%d pairs_in=%d pairs_out=%d",
		period, id, len(data.TopASNIn), len(data.TopASNOut),
		len(data.SankeyIn), len(data.SankeyOut))
}
