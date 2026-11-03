package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// CheckpointWAL runs a TRUNCATE checkpoint, which copies the WAL back into the
// main file and shrinks the -wal to zero bytes. Unlike the PASSIVE
// autocheckpoint it waits (up to busy_timeout) for readers to move past the
// WAL, so it is the only thing that reliably bounds the -wal file while the
// API keeps a constant read load on the pool.
//
// It returns busy=true when SQLite could not finish (a reader was still pinned);
// that is not an error, the next tick retries.
//
// TRUNCATE holds the writer lock while it copies frames into the main file, so
// copying a large WAL that way locks every writer out. A PASSIVE checkpoint runs
// first: it copies everything it can without taking the writer lock, leaving
// TRUNCATE only the frames appended since, so its lock window stays short.
//
// TRUNCATE also waits for readers through the busy handler, still holding the
// writer lock. With the pool's 5s busy_timeout, one long reader (a streamed
// daily rollup, a heavy API query) would lock writers out for 5s and make them
// fail with SQLITE_BUSY themselves. The checkpoint therefore runs on its own
// connection with checkpointBusyTimeout and simply reports busy instead.
func CheckpointWAL(ctx context.Context, db *sql.DB) (busy bool, walPages, moved int, err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, 0, 0, err
	}
	defer conn.Close()
	var prevTimeout int
	if err = conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&prevTimeout); err != nil {
		return false, 0, 0, err
	}
	if _, err = conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout=%d`, checkpointBusyTimeout.Milliseconds())); err != nil {
		return false, 0, 0, err
	}
	// Restore the pool default before the connection goes back to the pool.
	defer conn.ExecContext(context.Background(), fmt.Sprintf(`PRAGMA busy_timeout=%d`, prevTimeout)) //nolint:errcheck

	var b int
	if err = conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).Scan(&b, &walPages, &moved); err != nil {
		return false, walPages, moved, err
	}
	err = conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&b, &walPages, &moved)
	return b != 0, walPages, moved, err
}

// checkpointBusyTimeout bounds how long the TRUNCATE checkpoint may hold the
// writer lock while waiting for readers. Well under the 5s busy_timeout that
// every other writer uses, so a checkpoint can never make them fail.
const checkpointBusyTimeout = 250 * time.Millisecond

// IncrementalVacuum returns up to pages free pages to the OS. It is a no-op
// unless the file has auto_vacuum=INCREMENTAL (2); it reports the mode so the
// caller can log once that a one-off conversion is needed.
func IncrementalVacuum(ctx context.Context, db *sql.DB, pages int) (autoVacuum int, err error) {
	if err = db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return 0, err
	}
	if autoVacuum != 2 || pages <= 0 {
		return autoVacuum, nil
	}
	// PRAGMA arguments cannot be bound; pages is an int, so formatting is safe.
	// incremental_vacuum returns one (empty) row per page freed; drain them.
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, pages))
	if err != nil {
		return autoVacuum, err
	}
	for rows.Next() {
	}
	rows.Close()
	return autoVacuum, rows.Err()
}

// StartMaintenance checkpoints the WAL and incrementally vacuums every interval
// until ctx is done. interval <= 0 disables it.
func StartMaintenance(ctx context.Context, db *sql.DB, interval time.Duration, vacuumPages int) {
	if db == nil || interval <= 0 {
		log.Print("[SQLite] maintenance disabled")
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		warned := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			start := time.Now()
			busy, walPages, _, err := CheckpointWAL(ctx, db)
			if d := time.Since(start); d > time.Second {
				log.Printf("[SQLite] wal_checkpoint took %s (wal=%d pages)", d.Round(time.Millisecond), walPages)
			}
			switch {
			case err != nil:
				log.Printf("[SQLite] wal_checkpoint failed: %v", err)
			case busy:
				log.Printf("[SQLite] wal_checkpoint busy (wal=%d pages), retrying next tick", walPages)
			}
			mode, err := IncrementalVacuum(ctx, db, vacuumPages)
			if err != nil {
				log.Printf("[SQLite] incremental_vacuum failed: %v", err)
			} else if mode != 2 && vacuumPages > 0 && !warned {
				log.Printf("[SQLite] auto_vacuum=%d: freed pages are reused but the file never shrinks; "+
					"convert once offline with: PRAGMA auto_vacuum=INCREMENTAL; VACUUM; (see README)", mode)
				warned = true
			}
		}
	}()
}
