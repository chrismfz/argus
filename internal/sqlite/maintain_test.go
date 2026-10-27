package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCheckpointTruncatesWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rwc&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	// Keep autocheckpoint out of the way so the WAL is guaranteed to hold data.
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0; CREATE TABLE t (v BLOB)`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for i := 0; i < 200; i++ {
		if _, err := db.Exec(`INSERT INTO t VALUES (randomblob(4096))`); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("expected a non-empty WAL before checkpoint (err=%v)", err)
	}

	busy, _, _, err := CheckpointWAL(context.Background(), db)
	if err != nil || busy {
		t.Fatalf("CheckpointWAL: busy=%v err=%v", busy, err)
	}
	fi, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatalf("stat wal: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("WAL after TRUNCATE checkpoint = %d bytes; want 0", fi.Size())
	}
}

func TestIncrementalVacuumShrinksFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rwc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()

	// Not converted: reported as mode 0 and left alone.
	if mode, err := IncrementalVacuum(ctx, db, 100); err != nil || mode != 0 {
		t.Fatalf("default file: mode=%d err=%v; want 0, nil", mode, err)
	}

	if _, err := db.Exec(`PRAGMA auto_vacuum=INCREMENTAL; VACUUM; CREATE TABLE t (v BLOB)`); err != nil {
		t.Fatalf("convert: %v", err)
	}
	for i := 0; i < 300; i++ {
		if _, err := db.Exec(`INSERT INTO t VALUES (randomblob(4096))`); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if _, err := db.Exec(`DELETE FROM t`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	pageCount := func() int {
		var n int
		if err := db.QueryRow(`PRAGMA page_count`).Scan(&n); err != nil {
			t.Fatalf("page_count: %v", err)
		}
		return n
	}
	before := pageCount()
	mode, err := IncrementalVacuum(ctx, db, 1_000_000)
	if err != nil || mode != 2 {
		t.Fatalf("IncrementalVacuum: mode=%d err=%v", mode, err)
	}
	if after := pageCount(); after >= before {
		t.Fatalf("page_count %d → %d; want it to shrink", before, after)
	}
}
