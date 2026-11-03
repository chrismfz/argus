package sqlite

import (
	"database/sql"
	"fmt"
	"time"
)

// DefaultWriteBatchRows is the default for storage.write_batch_rows: how many
// rows a bulk prune or rollup writes per transaction before committing and
// letting other writers take the lock.
const DefaultWriteBatchRows = 5000

// BatchPause is the gap between two batches. Go's pool gives no fairness and
// SQLite's busy handler polls with sleeps, so a tight loop of back-to-back
// write transactions would starve every other writer just like one long one.
const BatchPause = 20 * time.Millisecond

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
		res, err := db.Exec(q, args...)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
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

// Flush writes the buffered rows in one transaction.
func (w *BatchWriter) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
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
	if err := tx.Commit(); err != nil {
		return err
	}
	w.n += int64(len(w.buf))
	w.buf = w.buf[:0]
	if w.batch > 0 {
		time.Sleep(BatchPause)
	}
	return nil
}

// Written reports how many rows have been committed so far.
func (w *BatchWriter) Written() int64 { return w.n }
