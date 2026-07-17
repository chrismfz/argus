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
	"sync"
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
// JSON tags shape the /debug/flowlog API consumed by the Flow Explorer UI.
type Row struct {
	Ts       int64  `json:"ts"` // unix seconds (flow end)
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Proto    uint8  `json:"proto"`
	TCPFlags uint8  `json:"tcp_flags"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
	InIface  uint32 `json:"in_iface"`
	OutIface uint32 `json:"out_iface"`
	SrcAS    uint32 `json:"src_as"`
	DstAS    uint32 `json:"dst_as"`
	Dir      string `json:"dir"` // "in" | "out" | ""
}

// Logger owns the flow-log database and its background writer + pruner.
type Logger struct {
	db    *sql.DB
	ch    chan Row
	cfg   Config
	seq   atomic.Uint64 // sampling counter
	drops atomic.Uint64 // flows dropped because the buffer was full

	stop      chan struct{} // closed by Close() to tell the loops to finish
	writerFin chan struct{} // closed by writeLoop when it has drained + exited
	closeOnce sync.Once
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

	dsn := "file:" + cfg.DBPath + "?mode=rwc" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
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
		db:        db,
		ch:        make(chan Row, cfg.BufferSize),
		cfg:       cfg,
		stop:      make(chan struct{}),
		writerFin: make(chan struct{}),
	}
	// The writer stops ONLY on Close() (not on ctx) so that flows flushed by the
	// batcher during its own shutdown — which happens before Close() via defer
	// LIFO ordering in main — are still drained. The pruner may stop on either.
	go l.writeLoop()
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

func (l *Logger) writeLoop() {
	defer close(l.writerFin)
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
		case <-l.stop:
			// Drain everything still queued, flush, and exit. Close() blocks on
			// writerFin before it touches the DB, so this always completes
			// before db.Close() — no lost final batch, no "database is closed".
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
	// 1-minute cadence bounds how far the file can overshoot MaxBytes between
	// checks (the size check is a couple of cheap PRAGMAs). The cap is still a
	// soft, lagging bound — see prune() and the config docs.
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stop:
			return
		case <-t.C:
			if d := l.drops.Swap(0); d > 0 {
				log.Printf("[flowlog] dropped %d flows in the last minute (writer behind / buffer full)", d)
			}
			if err := l.prune(); err != nil {
				log.Printf("[flowlog] prune failed: %v", err)
			}
		}
	}
}

// usedBytes returns the size of the LIVE data — total pages minus the freelist
// — so the pruner does not mistake reusable free pages (left by earlier deletes)
// for live data. Using total page_count here would inflate the per-row estimate
// after a burst and cause massive over-deletion.
func (l *Logger) usedBytes() (int64, error) {
	var pageCount, freeCount, pageSize int64
	if err := l.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := l.db.QueryRow(`PRAGMA freelist_count`).Scan(&freeCount); err != nil {
		return 0, err
	}
	if err := l.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return (pageCount - freeCount) * pageSize, nil
}

// fileBytes returns the total on-disk size of the main database file (live +
// free pages, excluding the WAL). Used for reporting, not for the prune target.
func (l *Logger) fileBytes() (int64, error) {
	var pageCount, pageSize int64
	if err := l.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := l.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}

// prune bounds the flow log's LIVE data to ~90% of MaxBytes. It does not shrink
// the file: deleted rows leave free pages that SQLite reuses for later inserts,
// so the file stabilises at a high-water mark near MaxBytes rather than growing
// forever. Deletes are chunked so a single statement never holds the write lock
// long enough to make the concurrent writer's INSERT time out (busy_timeout).
//
// The cap is a soft, lagging, main-file-only bound: between prune ticks the file
// can overshoot by up to one tick's worth of ingest, and the -wal file adds
// transient space on top. Size against your disk accordingly.
func (l *Logger) prune() error {
	if l.cfg.MaxBytes <= 0 { // negative/zero MaxBytes = no cap
		return nil
	}
	used, err := l.usedBytes()
	if err != nil {
		return err
	}
	if used <= l.cfg.MaxBytes {
		return nil // live data fits; any free pages will be reused, not grown past
	}
	var rowCount int64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&rowCount); err != nil {
		return err
	}
	if rowCount == 0 {
		return nil
	}
	bytesPerRow := float64(used) / float64(rowCount) // live bytes incl. index entries
	targetRows := int64(float64(l.cfg.MaxBytes) * 0.9 / bytesPerRow)
	toDelete := rowCount - targetRows
	if toDelete <= 0 {
		return nil
	}

	const chunk = 20000
	var deleted int64
	for toDelete > 0 {
		n := toDelete
		if n > chunk {
			n = chunk
		}
		res, err := l.db.Exec(
			`DELETE FROM flows WHERE rowid IN (SELECT rowid FROM flows ORDER BY rowid LIMIT ?)`, n)
		if err != nil {
			return err
		}
		got, _ := res.RowsAffected()
		if got == 0 {
			break
		}
		deleted += got
		toDelete -= got
	}
	file, _ := l.fileBytes()
	log.Printf("[flowlog] pruned %d oldest flows: live now ~%.2f GB (cap %.2f GB, file %.2f GB, %d rows)",
		deleted, float64(l.cfg.MaxBytes)*0.9/(1<<30), float64(l.cfg.MaxBytes)/(1<<30),
		float64(file)/(1<<30), rowCount-deleted)
	return nil
}

// Close stops the writer, waits for it to drain everything still queued, and
// only then closes the database. It is safe to call more than once. Because the
// writer stops on Close (not on the app context) and main defers Close AFTER the
// batcher's own Close, all in-flight flows are captured before shutdown.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		close(l.stop)
		<-l.writerFin // block until the writer has drained + flushed
	})
	return l.db.Close()
}
