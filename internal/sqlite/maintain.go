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
func CheckpointWAL(ctx context.Context, db *sql.DB) (busy bool, walPages, moved int, err error) {
	var b int
	err = db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&b, &walPages, &moved)
	return b != 0, walPages, moved, err
}

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
			busy, walPages, _, err := CheckpointWAL(ctx, db)
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
