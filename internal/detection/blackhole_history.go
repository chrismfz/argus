package detection

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"argus/internal/enrich"
)

// Event types for blackhole_events.
const (
	BHEventAnnounced = "announced"
	BHEventWithdrawn = "withdrawn"
	BHEventExpired   = "expired"
	BHEventSkipped   = "skipped"
)

// Source labels — who/what triggered the event.
const (
	BHSourceRule    = "rule"
	BHSourceAPI     = "api"
	BHSourceCleanup = "cleanup"
	BHSourceTTL     = "ttl"
	BHSourceFlush   = "flush"
)

// BlackholeEvent is a single audit-log entry for the blackhole_events table.
type BlackholeEvent struct {
	Timestamp  time.Time
	IP         string
	Prefix     string
	Event      string
	Source     string
	Rule       string
	Reason     string
	TTLSeconds int
	ASN        string
	ASNName    string
	Country    string
	PTR        string
}

// RecordBlackholeEvent appends one row to blackhole_events. If enrichment fields
// are empty and the global enricher is available, they are filled in from cache.
// Non-fatal: errors are logged but never returned, so callers can ignore.
func RecordBlackholeEvent(db *sql.DB, ev BlackholeEvent) {
	if db == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.IP == "" && ev.Prefix != "" {
		ev.IP = ipFromPrefix(ev.Prefix)
	}
	if ev.Prefix == "" && ev.IP != "" {
		ev.Prefix = ev.IP + "/32"
	}
	if (ev.ASN == "" || ev.ASNName == "" || ev.Country == "" || ev.PTR == "") && ev.IP != "" {
		fillEnrichment(&ev)
	}

	_, err := db.Exec(`
		INSERT INTO blackhole_events
			(ts, ip, prefix, event, source, rule, reason, ttl_seconds, asn, asn_name, country, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.Timestamp.Format(time.RFC3339),
		ev.IP,
		ev.Prefix,
		ev.Event,
		ev.Source,
		ev.Rule,
		ev.Reason,
		ev.TTLSeconds,
		ev.ASN,
		ev.ASNName,
		ev.Country,
		ev.PTR,
	)
	if err != nil {
		log.Printf("[blackhole_events] insert failed ip=%s event=%s: %v", ev.IP, ev.Event, err)
	}
}

func ipFromPrefix(prefix string) string {
	if i := strings.IndexByte(prefix, '/'); i >= 0 {
		return prefix[:i]
	}
	return prefix
}

func fillEnrichment(ev *BlackholeEvent) {
	if enrich.Global == nil {
		return
	}
	if net.ParseIP(ev.IP) == nil {
		return
	}
	if ev.ASN == "" && enrich.Global.Geo != nil {
		if n := enrich.Global.Geo.GetASNNumber(ev.IP); n != 0 {
			ev.ASN = fmt.Sprintf("AS%d", n)
		}
	}
	if ev.ASNName == "" && enrich.Global.Geo != nil {
		ev.ASNName = enrich.Global.Geo.GetASNName(ev.IP)
	}
	if ev.Country == "" && enrich.Global.Geo != nil {
		ev.Country = enrich.Global.Geo.GetCountry(ev.IP)
	}
	if ev.PTR == "" && enrich.Global.DNS != nil {
		ev.PTR = enrich.Global.DNS.LookupPTR(ev.IP)
	}
}

// PruneBlackholeEvents enforces retention: deletes rows older than maxAge,
// then trims to at most maxRows (FIFO by id).
func PruneBlackholeEvents(db *sql.DB, maxAge time.Duration, maxRows int) error {
	if db == nil {
		return nil
	}
	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
		res, err := db.Exec(`DELETE FROM blackhole_events WHERE ts < ?`, cutoff)
		if err != nil {
			return fmt.Errorf("prune by age: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[blackhole_events] pruned %d rows older than %s", n, maxAge)
		}
	}
	if maxRows > 0 {
		res, err := db.Exec(`
			DELETE FROM blackhole_events
			WHERE id IN (
				SELECT id FROM blackhole_events
				ORDER BY id DESC
				LIMIT -1 OFFSET ?
			)`, maxRows)
		if err != nil {
			return fmt.Errorf("prune by count: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[blackhole_events] pruned %d rows over cap of %d", n, maxRows)
		}
	}
	return nil
}
