package sqlite

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openBatchDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "b.db")+
		"?mode=rwc&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE t (ts INTEGER NOT NULL, v INTEGER NOT NULL);
		CREATE INDEX t_ts ON t(ts)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func count(t *testing.T, db *sql.DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestBatchWriterAndDeleteBatched(t *testing.T) {
	for _, batch := range []int{7, -1} { // several batches, and unbatched
		db := openBatchDB(t)
		w := NewBatchWriter(db, `INSERT INTO t (ts, v) VALUES (?, ?)`, batch)
		for i := 0; i < 100; i++ {
			if err := w.Add(i, i*10); err != nil {
				t.Fatalf("batch=%d add: %v", batch, err)
			}
		}
		if batch > 0 && w.Written() != 98 { // 14 full batches, 2 rows still buffered
			t.Fatalf("batch=%d: written before Flush = %d, want 98", batch, w.Written())
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("batch=%d flush: %v", batch, err)
		}
		if got := count(t, db, "1"); got != 100 || w.Written() != 100 {
			t.Fatalf("batch=%d: rows=%d written=%d, want 100", batch, got, w.Written())
		}

		// Delete ts < 50 — not a multiple of the batch, so the last chunk is short.
		n, err := DeleteBatched(db, "t", "ts < ?", batch, 50)
		if err != nil {
			t.Fatalf("batch=%d delete: %v", batch, err)
		}
		if n != 50 || count(t, db, "ts < 50") != 0 || count(t, db, "ts >= 50") != 50 {
			t.Fatalf("batch=%d: deleted=%d, left=%d", batch, n, count(t, db, "1"))
		}
	}
}

func TestRetryBusy(t *testing.T) {
	busy := errors.New("database is locked (5) (SQLITE_BUSY)")
	calls := 0
	err := retryBusy("test", func() error {
		calls++
		if calls < 2 {
			return busy
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("busy then ok: err=%v calls=%d, want nil after 2", err, calls)
	}
	calls = 0
	other := errors.New("constraint failed")
	if err := retryBusy("test", func() error { calls++; return other }); err != other || calls != 1 {
		t.Fatalf("non-busy error must not be retried: err=%v calls=%d", err, calls)
	}
}
