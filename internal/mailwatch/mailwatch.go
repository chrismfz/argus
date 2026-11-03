// Package mailwatch keeps a per-IP memory of outbound mail traffic: every flow
// from one of our addresses to a remote mail port (25/465/587 by default) is
// counted into fixed buckets (5 min by default) per (sender, port) — flows,
// bytes, distinct destination IPs and ASNs, top destinations — and persisted to
// SQLite, together with a long-lived per-sender row (first/last seen, totals).
//
// Detection rules only see the last flow_cache_max_window (60s) of traffic, so
// they cannot tell "a host that has always sent 500 mails a day" from "a host
// that never sent mail and started yesterday". This history is what answers
// that, and what the mail egress page and baseline alerts build on.
//
// Observe is on the ingest path: it takes one short mutex, does map updates
// only, and never touches SQLite. Persistence happens on the bucket timer.
package mailwatch

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// Config is the tracker's runtime configuration (see config.MailWatchConfig).
type Config struct {
	Ports      []uint16      // remote destination ports that count as mail
	Bucket     time.Duration // bucket width
	MaxSenders int           // distinct (sender, port) pairs per bucket; <= 0 = unlimited
	MaxDsts    int           // distinct destination IPs tracked per sender per bucket; <= 0 = unlimited
	TopN       int           // destinations / ASNs kept per bucket row
}

// Flow is the subset of a flow record the tracker needs. The caller has already
// decided the flow is outbound from one of our addresses.
type Flow struct {
	Src       string
	Dst       string
	DstPort   uint16
	DstAS     uint32
	DstASName string
	Bytes     uint64
	Packets   uint64
}

type key struct {
	src  string
	port uint16
}

type asnAgg struct {
	name  string
	flows uint64
}

type agg struct {
	flows, bytes, packets uint64
	dsts                  map[string]uint64 // dst IP → flows
	asns                  map[uint32]*asnAgg
	capped                bool // MaxDsts reached: uniq_dsts is a lower bound
}

// Tracker accumulates the current bucket in memory.
type Tracker struct {
	cfg   Config
	ports map[uint16]bool // read-only after New

	mu          sync.Mutex
	cur         map[key]*agg
	curStart    time.Time
	droppedKeys uint64 // flows not counted because MaxSenders was reached

	// Baseline alerts; only touched from the flush goroutine (see alerts.go).
	alerts    AlertConfig
	notify    func(Alert)
	lastAlert map[string]time.Time
	pending   []pendingBucket // flush goroutine only
	retryWait time.Duration   // first persist backoff, doubled per attempt
}

// New builds a tracker. Bucket defaults to 5m, TopN to 10.
func New(cfg Config) *Tracker {
	if cfg.Bucket <= 0 {
		cfg.Bucket = 5 * time.Minute
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 10
	}
	ports := make(map[uint16]bool, len(cfg.Ports))
	for _, p := range cfg.Ports {
		ports[p] = true
	}
	return &Tracker{
		cfg:       cfg,
		ports:     ports,
		cur:       make(map[key]*agg),
		curStart:  time.Now().Truncate(cfg.Bucket),
		retryWait: time.Second,
	}
}

// WantsPort is the cheap pre-filter for the ingest path (no lock).
func (t *Tracker) WantsPort(port uint16) bool { return t.ports[port] }

// Observe counts one outbound mail flow into the current bucket.
func (t *Tracker) Observe(f Flow) {
	if !t.ports[f.DstPort] {
		return
	}
	k := key{f.Src, f.DstPort}
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.cur[k]
	if a == nil {
		if t.cfg.MaxSenders > 0 && len(t.cur) >= t.cfg.MaxSenders {
			t.droppedKeys++
			return
		}
		a = &agg{dsts: make(map[string]uint64), asns: make(map[uint32]*asnAgg)}
		t.cur[k] = a
	}
	a.flows++
	a.bytes += f.Bytes
	a.packets += f.Packets
	if _, ok := a.dsts[f.Dst]; ok || t.cfg.MaxDsts <= 0 || len(a.dsts) < t.cfg.MaxDsts {
		a.dsts[f.Dst]++
	} else {
		a.capped = true
	}
	if as := a.asns[f.DstAS]; as != nil {
		as.flows++
	} else if t.cfg.MaxDsts <= 0 || len(a.asns) < t.cfg.MaxDsts {
		a.asns[f.DstAS] = &asnAgg{name: f.DstASName, flows: 1}
	}
}

// swap hands the finished bucket to the caller and starts a new one.
func (t *Tracker) swap(now time.Time) (time.Time, map[key]*agg, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	start, cur, dropped := t.curStart, t.cur, t.droppedKeys
	t.cur = make(map[key]*agg, len(cur))
	t.curStart = now.Truncate(t.cfg.Bucket)
	t.droppedKeys = 0
	return start, cur, dropped
}

// Run flushes a bucket at every bucket boundary and once more when ctx ends.
func (t *Tracker) Run(ctx context.Context, db *sql.DB) {
	for {
		now := time.Now()
		next := now.Truncate(t.cfg.Bucket).Add(t.cfg.Bucket)
		timer := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			t.flush(db, time.Now())
			return
		case fired := <-timer.C:
			t.flush(db, fired)
		}
	}
}

func (t *Tracker) flush(db *sql.DB, now time.Time) {
	start, cur, dropped := t.swap(now)
	if dropped > 0 {
		log.Printf("[mailwatch] bucket %s: %d flows not counted (mailwatch.max_senders=%d reached)",
			start.Format(time.RFC3339), dropped, t.cfg.MaxSenders)
	}
	if len(cur) > 0 {
		// Read what we knew before this bucket lands (new-sender check).
		t.pending = append(t.pending, pendingBucket{start, cur, t.alertContext(db, cur)})
	}
	if n := len(t.pending) - maxPending; n > 0 {
		log.Printf("[mailwatch] dropping %d unpersisted bucket(s) from %s: more than %d pending",
			n, t.pending[0].start.Format(time.RFC3339), maxPending)
		t.pending = t.pending[n:]
	}
	// Oldest first; on failure keep the rest for the next flush. The write
	// lock is contended at bucket boundaries, on shutdown (every subsystem
	// flushes at once) and for tens of seconds after startup.
	for len(t.pending) > 0 {
		b := t.pending[0]
		if err := t.persistRetry(db, b.start, b.cur); err != nil {
			log.Printf("[mailwatch] persist bucket %s (%d senders) failed, %d bucket(s) kept for the next flush: %v",
				b.start.Format(time.RFC3339), len(b.cur), len(t.pending), err)
			return
		}
		t.evaluate(db, b.start, b.cur, b.pre)
		t.pending = t.pending[1:]
	}
}

func (t *Tracker) persistRetry(db *sql.DB, start time.Time, cur map[key]*agg) error {
	var err error
	for attempt, wait := 1, t.retryWait; attempt <= persistAttempts; attempt, wait = attempt+1, wait*2 {
		if err = t.persist(db, start, cur); err == nil {
			return nil
		}
		if attempt < persistAttempts {
			time.Sleep(wait)
		}
	}
	return err
}

// pendingBucket is a finished bucket not yet written to SQLite.
type pendingBucket struct {
	start time.Time
	cur   map[key]*agg
	pre   preContext
}

const (
	persistAttempts = 4  // per flush, 1s/2s/4s apart (each also waits busy_timeout)
	maxPending      = 12 // unpersisted buckets kept for retry (1h at 5m buckets)
)

// TopDst / TopASN are the JSON elements of a bucket row's top lists.
type TopDst struct {
	IP    string `json:"ip"`
	Flows uint64 `json:"flows"`
}

type TopASN struct {
	ASN   uint32 `json:"asn"`
	Name  string `json:"name,omitempty"`
	Flows uint64 `json:"flows"`
}

func topDsts(m map[string]uint64, n int) []TopDst {
	out := make([]TopDst, 0, len(m))
	for ip, f := range m {
		out = append(out, TopDst{ip, f})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topASNs(m map[uint32]*asnAgg, n int) []TopASN {
	out := make([]TopASN, 0, len(m))
	for asn, a := range m {
		out = append(out, TopASN{asn, a.name, a.flows})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].ASN < out[j].ASN
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// InitSchema creates the mailwatch tables.
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(`
	-- One row per (sender, remote mail port, bucket).
	CREATE TABLE IF NOT EXISTS mail_egress_buckets (
		ts        INTEGER NOT NULL,           -- bucket start, unix seconds
		src_ip    TEXT    NOT NULL,
		port      INTEGER NOT NULL,
		flows     INTEGER NOT NULL,
		packets   INTEGER NOT NULL,
		bytes     INTEGER NOT NULL,
		uniq_dsts INTEGER NOT NULL,
		uniq_asns INTEGER NOT NULL,
		capped    INTEGER NOT NULL DEFAULT 0, -- 1 = uniq_dsts is a lower bound (max_dsts reached)
		top_dsts  TEXT    NOT NULL DEFAULT '[]',
		top_asns  TEXT    NOT NULL DEFAULT '[]',
		PRIMARY KEY (src_ip, port, ts)
	) WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS idx_mailegress_ts ON mail_egress_buckets(ts);

	-- Long-lived memory per sender: when did this IP first/last send mail.
	CREATE TABLE IF NOT EXISTS mail_egress_senders (
		src_ip        TEXT PRIMARY KEY,
		first_seen    INTEGER NOT NULL,
		last_seen     INTEGER NOT NULL,
		total_flows   INTEGER NOT NULL DEFAULT 0,
		total_bytes   INTEGER NOT NULL DEFAULT 0,
		max_uniq_dsts INTEGER NOT NULL DEFAULT 0  -- busiest bucket ever, distinct destinations
	);

	-- Baseline alerts (new sender / spike over the sender's own p95).
	CREATE TABLE IF NOT EXISTS mail_egress_alerts (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts        INTEGER NOT NULL,           -- bucket start
		src_ip    TEXT    NOT NULL,
		port      INTEGER NOT NULL,
		kind      TEXT    NOT NULL,           -- new_sender | spike
		severity  TEXT    NOT NULL,
		uniq_dsts INTEGER NOT NULL,
		flows     INTEGER NOT NULL,
		baseline  REAL    NOT NULL DEFAULT 0,
		threshold INTEGER NOT NULL DEFAULT 0,
		top_dsts  TEXT    NOT NULL DEFAULT '[]',
		top_asns  TEXT    NOT NULL DEFAULT '[]'
	);
	CREATE INDEX IF NOT EXISTS idx_mailalerts_ts ON mail_egress_alerts(ts);
	CREATE INDEX IF NOT EXISTS idx_mailalerts_ip ON mail_egress_alerts(src_ip, ts);`)
	return err
}

func (t *Tracker) persist(db *sql.DB, start time.Time, cur map[key]*agg) error {
	ts := start.Unix()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	bucketStmt, err := tx.Prepare(`
		INSERT INTO mail_egress_buckets
			(ts, src_ip, port, flows, packets, bytes, uniq_dsts, uniq_asns, capped, top_dsts, top_asns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(src_ip, port, ts) DO UPDATE SET
			flows = flows + excluded.flows,
			packets = packets + excluded.packets,
			bytes = bytes + excluded.bytes,
			uniq_dsts = max(uniq_dsts, excluded.uniq_dsts),
			uniq_asns = max(uniq_asns, excluded.uniq_asns),
			capped = max(capped, excluded.capped),
			top_dsts = excluded.top_dsts,
			top_asns = excluded.top_asns`)
	if err != nil {
		return err
	}
	defer bucketStmt.Close()

	senderStmt, err := tx.Prepare(`
		INSERT INTO mail_egress_senders (src_ip, first_seen, last_seen, total_flows, total_bytes, max_uniq_dsts)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(src_ip) DO UPDATE SET
			first_seen = min(first_seen, excluded.first_seen),
			last_seen = max(last_seen, excluded.last_seen),
			total_flows = total_flows + excluded.total_flows,
			total_bytes = total_bytes + excluded.total_bytes,
			max_uniq_dsts = max(max_uniq_dsts, excluded.max_uniq_dsts)`)
	if err != nil {
		return err
	}
	defer senderStmt.Close()

	for k, a := range cur {
		dsts, err := json.Marshal(topDsts(a.dsts, t.cfg.TopN))
		if err != nil {
			return err
		}
		asns, err := json.Marshal(topASNs(a.asns, t.cfg.TopN))
		if err != nil {
			return err
		}
		capped := 0
		if a.capped {
			capped = 1
		}
		if _, err := bucketStmt.Exec(ts, k.src, k.port, a.flows, a.packets, a.bytes,
			len(a.dsts), len(a.asns), capped, string(dsts), string(asns)); err != nil {
			return fmt.Errorf("bucket %s:%d: %w", k.src, k.port, err)
		}
		if _, err := senderStmt.Exec(k.src, ts, ts, a.flows, a.bytes, len(a.dsts)); err != nil {
			return fmt.Errorf("sender %s: %w", k.src, err)
		}
	}
	return tx.Commit()
}

// Prune deletes buckets older than bucketAge and senders not seen for
// senderAge. A value <= 0 keeps that table forever.
func Prune(db *sql.DB, bucketAge, senderAge time.Duration) error {
	if db == nil {
		return nil
	}
	if bucketAge > 0 {
		res, err := db.Exec(`DELETE FROM mail_egress_buckets WHERE ts < ?`, time.Now().Add(-bucketAge).Unix())
		if err != nil {
			return fmt.Errorf("prune mail_egress_buckets: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[mailwatch] pruned %d buckets older than %s", n, bucketAge)
		}
	}
	if senderAge > 0 {
		res, err := db.Exec(`DELETE FROM mail_egress_senders WHERE last_seen < ?`, time.Now().Add(-senderAge).Unix())
		if err != nil {
			return fmt.Errorf("prune mail_egress_senders: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[mailwatch] pruned %d senders idle for %s", n, senderAge)
		}
	}
	return nil
}
