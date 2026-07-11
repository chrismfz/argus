package detection

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"argus/internal/bgp"
)

// PruneDetections deletes rows from the detections table whose last_seen is
// older than maxAge. The table would otherwise grow without bound, one row per
// (ip, rule) ever seen (including the "bh-escalate:*" escalation counters).
// maxAge <= 0 disables pruning (keep forever). Comparison goes through SQLite's
// datetime() so it is correct across timezone offsets / DST.
func PruneDetections(db *sql.DB, maxAge time.Duration) error {
	if maxAge <= 0 {
		return nil
	}
	res, err := db.Exec(
		`DELETE FROM detections WHERE datetime(last_seen) < datetime('now', ?)`,
		fmt.Sprintf("-%d seconds", int64(maxAge.Seconds())),
	)
	if err != nil {
		return fmt.Errorf("prune detections: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[detections] pruned %d rows older than %s", n, maxAge)
	}
	return nil
}

// Κάνει withdraw και διαγράφει expired blackholes
func CleanupExpiredBlackholes(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT prefix, rule FROM blackholes
		WHERE expires_at <= datetime('now')
	`)
	if err != nil {
		return fmt.Errorf("failed to query expired blackholes: %w", err)
	}
	defer rows.Close()

	type expiredRow struct {
		prefix string
		rule   string
	}
	var expired []expiredRow
	for rows.Next() {
		var r expiredRow
		var rule sql.NullString
		if err := rows.Scan(&r.prefix, &rule); err == nil {
			if rule.Valid {
				r.rule = rule.String
			}
			expired = append(expired, r)
		}
	}

	for _, r := range expired {
		prefix := r.prefix
		err := bgp.WithdrawPrefix(prefix)
		if err != nil {
			log.Printf("[WARN] Failed to withdraw expired prefix %s: %v", prefix, err)
		} else {
			log.Printf("[INFO] Withdrawn expired blackhole %s", prefix)
		}

		// Διαγραφή από SQLite
		_, err = db.Exec(`DELETE FROM blackholes WHERE prefix = ?`, prefix)
		if err != nil {
			log.Printf("[ERROR] Failed to delete expired prefix %s from DB: %v", prefix, err)
		}

		RecordBlackholeEvent(db, BlackholeEvent{
			Prefix: prefix,
			Event:  BHEventExpired,
			Source: BHSourceCleanup,
			Rule:   r.rule,
			Reason: "TTL expired (cleanup)",
		})
	}

	if len(expired) > 0 {
		log.Printf("[CLEANUP] Removed %d expired blackholes", len(expired))
	}

	return nil
}
