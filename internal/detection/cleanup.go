package detection

import (
	"database/sql"
	"fmt"
	"log"
//	"time"
	"argus/internal/bgp"
)

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
