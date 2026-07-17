// Package flowlog implements ROADMAP Phase 2 Tier 0: an optional raw flow log.
//
// Every enriched flow (5-tuple + bytes/packets/ifaces/ASNs/direction) is
// appended to a dedicated SQLite file, pruned by SIZE rather than age, so the
// operator trades a fixed disk budget for "keep the most recent N GB of every
// flow". This is the forensic store that answers "what did IP X do at 03:00?"
// — a question the aggregated tables (top-N, rolled up) cannot.
//
// Design constraints:
//   - Disabled by default. It is the only argus subsystem that can write a lot.
//   - Never blocks the ingest hot path: Enqueue does a non-blocking send onto a
//     bounded channel; if the writer can't keep up, flows are dropped and
//     counted (logged), never queued unboundedly or written synchronously.
//   - Its own SQLite file (WAL) so the write-heavy log never contends on the
//     detection/telemetry database's lock.
package flowlog

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// Global is the package-level Logger singleton, or nil when the flow log is
// disabled. Callers must nil-check before Enqueue.
var Global *Logger

// Config mirrors config.FlowLogConfig with normalised values.
type Config struct {
	DBPath     string
	MaxBytes   int64 // 0 or negative = no size cap
	SampleRate int   // write 1 of every N flows (<=1 = every flow)
	BufferSize int
	BatchSize  int
}

// Row is one enriched flow record. Defined here (not in the flow package) so
// flowlog has no import cycle; the batcher maps *flow.FlowRecord → Row.
type Row struct {
	Ts       int64 // unix seconds (flow end)
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	TCPFlags uint8
	Bytes    uint64
	Packets  uint64
	InIface  uint32
	OutIface uint32
	SrcAS    uint32
	DstAS    uint32
	Dir      string // "in" | "out" | ""
}

// Logger owns the flow-log database and its background writer + pruner.
type Logger struct {
	db    *sql.DB
	ch    chan Row
	cfg   Config
	seq   atomic.Uint64 // sampling counter
	drops atomic.Uint64 // flows dropped because the buffer was full
}

const schema = `
CREATE TABLE IF NOT EXISTS flows (
  ts        INTEGER NOT NULL,
  src_ip    TEXT    NOT NULL,
  dst_ip    TEXT    NOT NULL,
  src_port  INTEGER NOT NULL,
  dst_port  INTEGER NOT NULL,
  proto     INTEGER NOT NULL,
  tcp_flags INTEGER NOT NULL,
  bytes     INTEGER NOT NULL,
  packets   INTEGER NOT NULL,
  in_iface  INTEGER NOT NULL,
  out_iface INTEGER NOT NULL,
  src_as    INTEGER NOT NULL,
  dst_as    INTEGER NOT NULL,
  dir       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_ts  ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip, ts);
`

// Init opens (creating if needed) the flow-log database, starts the writer and
// pruner goroutines, and sets Global. Call once from main when enabled.
func Init(ctx context.Context, cfg Config) (*Logger, error) {
	if cfg.SampleRate < 1 {
		cfg.SampleRate = 1
	}
	if cfg.BufferSize < 1 {
		cfg.BufferSize = 65536
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1000
	}

	// auto_vacuum=INCREMENTAL must be set before the schema is created for the
	// pruner's PRAGMA incremental_vacuum to return freed pages to the OS.
	dsn := "file:" + cfg.DBPath + "?mode=rwc" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=auto_vacuum(INCREMENTAL)" +
		"&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open flowlog db: %w", err)
	}
	db.SetMaxOpenConns(2) // one writer + one reader (debug queries)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("flowlog schema: %w", err)
	}

	l := &Logger{
		db:  db,
		ch:  make(chan Row, cfg.BufferSize),
		cfg: cfg,
	}
	go l.writeLoop(ctx)
	go l.pruneLoop(ctx)
	Global = l
	return l, nil
}

// Enqueue records one flow. Safe on the ingest hot path: it samples, then does
// a non-blocking send — a full buffer drops the flow (counted) rather than
// blocking. A nil Logger is a no-op so callers need not guard beyond the
// package-level Global check.
func (l *Logger) Enqueue(r Row) {
	if l == nil {
		return
	}
	if l.cfg.SampleRate > 1 && l.seq.Add(1)%uint64(l.cfg.SampleRate) != 0 {
		return
	}
	select {
	case l.ch <- r:
	default:
		l.drops.Add(1)
	}
}

func (l *Logger) writeLoop(ctx context.Context) {
	batch := make([]Row, 0, l.cfg.BatchSize)
	flushTick := time.NewTicker(1 * time.Second)
	defer flushTick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := l.writeBatch(batch); err != nil {
			log.Printf("[flowlog] write batch (%d rows) failed: %v", len(batch), err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain what is already queued, then flush and exit.
			for {
				select {
				case r := <-l.ch:
					batch = append(batch, r)
					if len(batch) >= l.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case r := <-l.ch:
			batch = append(batch, r)
			if len(batch) >= l.cfg.BatchSize {
				flush()
			}
		case <-flushTick.C:
			flush()
		}
	}
}

func (l *Logger) writeBatch(batch []Row) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`
		INSERT INTO flows
			(ts, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags,
			 bytes, packets, in_iface, out_iface, src_as, dst_as, dir)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range batch {
		if _, err := stmt.Exec(
			r.Ts, r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Proto, r.TCPFlags,
			r.Bytes, r.Packets, r.InIface, r.OutIface, r.SrcAS, r.DstAS, r.Dir,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (l *Logger) pruneLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d := l.drops.Swap(0); d > 0 {
				log.Printf("[flowlog] dropped %d flows since last check (writer behind / buffer full)", d)
			}
			if err := l.prune(); err != nil {
				log.Printf("[flowlog] prune failed: %v", err)
			}
		}
	}
}

// sizeBytes returns the on-disk size of the main database file (excluding the
// WAL, which checkpoints back into it).
func (l *Logger) sizeBytes() (int64, error) {
	var pageCount, pageSize int64
	if err := l.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := l.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}

// prune bounds the flow log to roughly MaxBytes. It does NOT try to shrink the
// file — instead it deletes the oldest rows so the live data fits in ~90% of the
// budget, and lets SQLite reuse the freed pages for subsequent inserts. The
// file therefore stabilises at a high-water mark near MaxBytes rather than
// growing without bound. (This sidesteps the WAL + incremental_vacuum
// unreliability of file truncation; incremental_vacuum is still issued as a
// best-effort return of pages to the OS when auto_vacuum is in effect.)
func (l *Logger) prune() error {
	if l.cfg.MaxBytes <= 0 {
		return nil
	}
	size, err := l.sizeBytes()
	if err != nil {
		return err
	}
	if size <= l.cfg.MaxBytes {
		return nil
	}
	var rowCount int64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&rowCount); err != nil {
		return err
	}
	if rowCount == 0 {
		return nil
	}
	// Bytes per row including its index entries.
	bytesPerRow := float64(size) / float64(rowCount)
	targetRows := int64(float64(l.cfg.MaxBytes) * 0.9 / bytesPerRow)
	toDelete := rowCount - targetRows
	if toDelete <= 0 {
		return nil
	}
	res, err := l.db.Exec(
		`DELETE FROM flows WHERE rowid IN (SELECT rowid FROM flows ORDER BY rowid LIMIT ?)`, toDelete)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	// Best-effort: return freed pages to the OS (no-op / harmless if auto_vacuum
	// is not incremental on this file).
	_, _ = l.db.Exec(`PRAGMA incremental_vacuum`)
	log.Printf("[flowlog] pruned %d oldest flows to stay near %.2f GB (was %.2f GB, %d rows)",
		n, float64(l.cfg.MaxBytes)/(1<<30), float64(size)/(1<<30), rowCount)
	return nil
}

// Close stops accepting writes; the writer drains via context cancellation.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.db.Close()
}
