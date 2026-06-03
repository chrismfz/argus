package detection

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
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

// ── async audit-log writer ────────────────────────────────────────────────────
//
// RecordBlackholeEvent runs in the detection hot path (rule matches, safeguard
// skips, TTL expiry). Both the enrichment (which may do a blocking reverse-DNS
// lookup) and the INSERT contend for the process-wide single SQLite connection
// (db.SetMaxOpenConns(1)). Doing them synchronously here stalls detection and
// starves read endpoints like /blackhole-list. So we hand the event to a single
// background worker: callers return immediately, and enrichment + INSERT happen
// off the hot path.

const (
	bhEventQueueSize = 1024
	bhEventWriteTO   = 5 * time.Second
	// skipped events repeat on every flow batch for the same protected/myNets
	// target — collapse them so they don't flood the audit log (and the DB).
	bhSkipCooldown = 60 * time.Second
)

type bhEventReq struct {
	db *sql.DB
	ev BlackholeEvent
}

var (
	bhEventCh    chan bhEventReq
	bhWorkerOnce sync.Once

	bhSkipMu   sync.Mutex
	bhSkipSeen = make(map[string]time.Time)
)

func startBHWorker() {
	bhEventCh = make(chan bhEventReq, bhEventQueueSize)
	go func() {
		for req := range bhEventCh {
			writeBlackholeEvent(req.db, req.ev)
		}
	}()
}

// allowSkipEvent rate-limits "skipped" events per IP so repeated matches against
// the same protected/myNets target don't generate a row on every flow batch.
func allowSkipEvent(ip string) bool {
	if ip == "" {
		return true
	}
	now := time.Now()
	bhSkipMu.Lock()
	defer bhSkipMu.Unlock()
	if last, ok := bhSkipSeen[ip]; ok && now.Sub(last) < bhSkipCooldown {
		return false
	}
	bhSkipSeen[ip] = now
	if len(bhSkipSeen) > 10000 { // bound the map
		for k, t := range bhSkipSeen {
			if now.Sub(t) > bhSkipCooldown {
				delete(bhSkipSeen, k)
			}
		}
	}
	return true
}

// RecordBlackholeEvent queues one row for the blackhole_events audit log. It is
// non-blocking: cheap field normalisation happens inline, then the event is
// handed to a background worker that performs enrichment and the INSERT. Safe to
// call from the detection hot path. Non-fatal: drops/errors are only logged.
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
	if ev.Event == BHEventSkipped && !allowSkipEvent(ev.IP) {
		return
	}

	bhWorkerOnce.Do(startBHWorker)
	select {
	case bhEventCh <- bhEventReq{db: db, ev: ev}:
	default:
		log.Printf("[blackhole_events] queue full, dropping event ip=%s event=%s", ev.IP, ev.Event)
	}
}

// writeBlackholeEvent fills enrichment (possibly a blocking PTR lookup) and
// inserts the row. Runs only in the background worker, never in the hot path.
func writeBlackholeEvent(db *sql.DB, ev BlackholeEvent) {
	if (ev.ASN == "" || ev.ASNName == "" || ev.Country == "" || ev.PTR == "") && ev.IP != "" {
		fillEnrichment(&ev)
	}

	ctx, cancel := context.WithTimeout(context.Background(), bhEventWriteTO)
	defer cancel()

	_, err := db.ExecContext(ctx, `
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
