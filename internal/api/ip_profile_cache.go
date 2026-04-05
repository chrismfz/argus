package api

import (
	"argus/internal/config"
	"database/sql"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type ipProfileRow struct {
	IP        string
	ASN       string
	ASNName   string
	Country   string
	PTR       string
	FirstSeen string
	LastSeen  string
	Hits      int
	UpdatedAt string
}

var ipProfileCleanupOnce sync.Once

func startIPProfileCleanupJob() {
	ipProfileCleanupOnce.Do(func() {
		if DB == nil || config.AppConfig == nil {
			return
		}
		interval := config.AppConfig.IPProfile.CleanupInterval
		if interval <= 0 {
			interval = 15 * time.Minute
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				cleanupIPProfileCache(DB, time.Now(), config.AppConfig.IPProfile.Retention, config.AppConfig.IPProfile.MaxEntries)
			}
		}()
	})
}

func lookupFreshIPProfile(ip string, now time.Time, staleAfter time.Duration) (*ipProfileRow, bool, error) {
	if DB == nil {
		return nil, false, nil
	}
	row := &ipProfileRow{}
	err := DB.QueryRow(`
		SELECT ip, asn, asn_name, country, ptr, first_seen, last_seen, hits, updated_at
		FROM ip_profile
		WHERE ip = ?
	`, ip).Scan(&row.IP, &row.ASN, &row.ASNName, &row.Country, &row.PTR, &row.FirstSeen, &row.LastSeen, &row.Hits, &row.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	updatedAt, err := time.Parse(time.RFC3339, row.UpdatedAt)
	if err != nil {
		return nil, false, nil
	}
	if now.Sub(updatedAt) > staleAfter {
		return row, false, nil
	}
	if _, err := DB.Exec(`UPDATE ip_profile SET hits = hits + 1, last_seen = ? WHERE ip = ?`, now.Format(time.RFC3339), ip); err != nil {
		log.Printf("[WARN] ip_profile hit update failed ip=%s err=%v", ip, err)
	}
	row.Hits++
	row.LastSeen = now.Format(time.RFC3339)
	return row, true, nil
}

func upsertIPProfile(row *ipProfileRow, now time.Time) error {
	if DB == nil {
		return nil
	}
	ts := now.Format(time.RFC3339)
	_, err := DB.Exec(`
		INSERT INTO ip_profile (
			ip, asn, asn_name, country, ptr, first_seen, last_seen, hits, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(ip) DO UPDATE SET
			asn = excluded.asn,
			asn_name = excluded.asn_name,
			country = excluded.country,
			ptr = excluded.ptr,
			last_seen = excluded.last_seen,
			hits = ip_profile.hits + 1,
			updated_at = excluded.updated_at
	`, row.IP, row.ASN, row.ASNName, row.Country, row.PTR, ts, ts, ts)
	return err
}

func cleanupIPProfileCache(db *sql.DB, now time.Time, retention time.Duration, maxEntries int) {
	if db == nil {
		return
	}
	cutoff := now.Add(-retention).Format(time.RFC3339)
	if _, err := db.Exec(`DELETE FROM ip_profile WHERE updated_at < ?`, cutoff); err != nil {
		log.Printf("[WARN] ip_profile ttl cleanup failed: %v", err)
	}
	if maxEntries > 0 {
		if _, err := db.Exec(`
			DELETE FROM ip_profile
			WHERE ip IN (
				SELECT ip
				FROM ip_profile
				ORDER BY updated_at DESC
				LIMIT -1 OFFSET ?
			)
		`, maxEntries); err != nil {
			log.Printf("[WARN] ip_profile cap cleanup failed: %v", err)
		}
	}
}

func fetchIPDetectionsHistory(ip string, limit int) ([]map[string]interface{}, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`
		SELECT rule, reason, count, first_seen, last_seen
		FROM detections
		WHERE ip = ?
		ORDER BY last_seen DESC
		LIMIT ?
	`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]map[string]interface{}, 0)
	for rows.Next() {
		var rule, reason, firstSeen, lastSeen sql.NullString
		var count sql.NullInt64
		if err := rows.Scan(&rule, &reason, &count, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"detector":   strings.TrimSpace(rule.String),
			"risk":       strings.TrimSpace(reason.String),
			"count":      count.Int64,
			"first_seen": strings.TrimSpace(firstSeen.String),
			"last_seen":  strings.TrimSpace(lastSeen.String),
		})
	}
	return out, rows.Err()
}

func fetchLatestBlackholeEvent(ip string) (map[string]interface{}, error) {
	if DB == nil {
		return nil, nil
	}
	cidrSuffix := "/32"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		cidrSuffix = "/128"
	}
	var (
		prefix, ts, expires, rule, reason, asn, asnName, country, ptr sql.NullString
	)
	err := DB.QueryRow(`
		SELECT prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr
		FROM blackholes
		WHERE prefix = ? OR prefix = ?
		ORDER BY timestamp DESC
		LIMIT 1
	`, ip, ip+cidrSuffix).Scan(&prefix, &ts, &expires, &rule, &reason, &asn, &asnName, &country, &ptr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	active := false
	if expires.Valid {
		if parsed, err := time.Parse(time.RFC3339, expires.String); err == nil {
			active = parsed.After(time.Now())
		}
	}
	return map[string]interface{}{
		"prefix":      prefix.String,
		"timestamp":   ts.String,
		"expires_at":  expires.String,
		"rule":        rule.String,
		"reason":      reason.String,
		"asn":         asn.String,
		"asn_name":    asnName.String,
		"country":     country.String,
		"ptr":         ptr.String,
		"is_active":   active,
		"matched_ip":  ip,
		"event_table": "blackholes",
	}, nil
}
