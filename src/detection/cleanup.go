package detection

import (
	"database/sql"
	"fmt"
	"log"
//	"time"
	"flowenricher/bgp"
)

// Κάνει withdraw και διαγράφει expired blackholes
func CleanupExpiredBlackholes(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT prefix FROM blackholes
		WHERE expires_at <= datetime('now')
	`)
	if err != nil {
		return fmt.Errorf("failed to query expired blackholes: %w", err)
	}
	defer rows.Close()

	var expired []string
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err == nil {
			expired = append(expired, prefix)
		}
	}

	for _, prefix := range expired {
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
	}

	if len(expired) > 0 {
		log.Printf("[CLEANUP] Removed %d expired blackholes", len(expired))
	}

	return nil
}
