package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// DefaultWriteBatchRows is the default for storage.write_batch_rows: how many
// rows a bulk prune or rollup writes per transaction before committing and
// letting other writers take the lock.
const DefaultWriteBatchRows = 5000

// BatchPause is the gap between two batches. SQLite's lock is not fair: a
// writer blocked on it sleeps in the busy handler and retries, and those sleeps
// grow to 100ms. A gap shorter than that (it was 20ms) is usually missed, so a
// loop of back-to-back batches starved other writers into SQLITE_BUSY just like
// one long transaction did (seen in production on the first deploy). The gap
// must exceed the longest busy-handler sleep.
const BatchPause = 150 * time.Millisecond

// busyAttempts / busyBackoff: a background batch that still loses the lock
// after the full busy_timeout is retried instead of aborting the whole job
// (a daily rollup takes many minutes; one lost race would postpone it 24h).
const (
	busyAttempts = 4
	busyBackoff  = 2 * time.Second
)

// slowBatch is when a single batch transaction gets logged: anything that
// holds the write lock this long is close to failing other writers.
const slowBatch = 2 * time.Second

// IsBusy reports whether err is SQLite's "database is locked" (SQLITE_BUSY).
func IsBusy(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "SQLITE_BUSY") ||
		strings.Contains(err.Error(), "database is locked"))
}

// retryBusy runs fn, retrying it with a backoff while it fails with SQLITE_BUSY.
// fn must be one whole transaction, so a retry never repeats committed work.
func retryBusy(what string, fn func() error) error {
	var err error
	for attempt := 1; attempt <= busyAttempts; attempt++ {
		start := time.Now()
		err = fn()
		if d := time.Since(start); d > slowBatch {
			log.Printf("[SQLite] slow batch %s: %s (err=%v)", what, d.Round(time.Millisecond), err)
		}
		if !IsBusy(err) || attempt == busyAttempts {
			return err
		}
		time.Sleep(busyBackoff * time.Duration(attempt))
	}
	return err
}

// DeleteBatched runs `DELETE FROM table WHERE <where>` in chunks of batch rows,
// committing each chunk separately so the write lock is never held for longer
// than one chunk. table must be a rowid table and where should be served by an
// index. batch < 0 runs a single unbatched DELETE (the pre-batching behaviour);
// 0 means DefaultWriteBatchRows. Returns the number of rows deleted.
//
// table and where are interpolated, so they must be constants, never user input.
func DeleteBatched(db *sql.DB, table, where string, batch int, args ...any) (int64, error) {
	if batch == 0 {
		batch = DefaultWriteBatchRows
	}
	if batch < 0 {
		res, err := db.Exec(`DELETE FROM `+table+` WHERE `+where, args...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	q := fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s LIMIT %d)`,
		table, table, where, batch)
	var total int64
	for {
		var n int64
		err := retryBusy("delete "+table, func() error {
			res, err := db.Exec(q, args...)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(batch) {
			return total, nil
		}
		time.Sleep(BatchPause)
	}
}

// BatchWriter buffers rows for one INSERT statement and writes them in
// transactions of at most batch rows, so a bulk write (a daily rollup can be
// millions of rows) never holds the write lock for long. Each Flush is its own
// transaction: a failure leaves the earlier batches committed, so callers that
// need all-or-nothing must make the work idempotent and mark completion last.
type BatchWriter struct {
	db    *sql.DB
	query string
	batch int
	buf   [][]any
	n     int64
}

// NewBatchWriter returns a writer for query (an INSERT with placeholders).
// batch follows DeleteBatched: 0 = default, < 0 = buffer everything and write
// it in a single transaction on Flush.
func NewBatchWriter(db *sql.DB, query string, batch int) *BatchWriter {
	if batch == 0 {
		batch = DefaultWriteBatchRows
	}
	return &BatchWriter{db: db, query: query, batch: batch}
}

// Add queues one row, flushing when the batch is full.
func (w *BatchWriter) Add(args ...any) error {
	w.buf = append(w.buf, args)
	if w.batch > 0 && len(w.buf) >= w.batch {
		return w.Flush()
	}
	return nil
}

// Flush writes the buffered rows in one transaction, retrying it on SQLITE_BUSY.
func (w *BatchWriter) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	if err := retryBusy("insert", w.write); err != nil {
		return err
	}
	w.n += int64(len(w.buf))
	w.buf = w.buf[:0]
	if w.batch > 0 {
		time.Sleep(BatchPause)
	}
	return nil
}

func (w *BatchWriter) write() error {
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(w.query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, args := range w.buf {
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Written reports how many rows have been committed so far.
func (w *BatchWriter) Written() int64 { return w.n }
