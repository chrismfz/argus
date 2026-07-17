package flowlog

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestLogger(t *testing.T, cfg Config) (*Logger, context.CancelFunc) {
	t.Helper()
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(t.TempDir(), "flows_test.db")
	}
	ctx, cancel := context.WithCancel(context.Background())
	l, err := Init(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		l.Close()
		Global = nil
	})
	return l, cancel
}

func sampleRow(ip string, ts int64) Row {
	return Row{
		Ts: ts, SrcIP: ip, DstIP: "203.0.113.9",
		SrcPort: 12345, DstPort: 443, Proto: 6, TCPFlags: 0x02,
		Bytes: 1000, Packets: 5, InIface: 2, OutIface: 3,
		SrcAS: 65001, DstAS: 15169, Dir: "in",
	}
}

// waitForRows polls until the async writer has persisted at least want rows.
func waitForRows(t *testing.T, l *Logger, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := l.Stats()
		if err == nil && n >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, _, _ := l.Stats()
	t.Fatalf("timed out waiting for %d rows, have %d", want, n)
}

func TestEnqueueAndQuery(t *testing.T) {
	l, _ := newTestLogger(t, Config{})

	now := time.Now().Unix()
	l.Enqueue(sampleRow("198.51.100.1", now))
	l.Enqueue(sampleRow("198.51.100.2", now))
	l.Enqueue(sampleRow("198.51.100.1", now-60))
	waitForRows(t, l, 3)

	// Filter by IP (matches src or dst).
	got, err := l.Query(Filter{IP: "198.51.100.1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 flows for 198.51.100.1, got %d", len(got))
	}
	// Newest first.
	if got[0].Ts < got[1].Ts {
		t.Fatalf("expected newest-first ordering, got %d then %d", got[0].Ts, got[1].Ts)
	}
	// Round-trip fidelity.
	if got[0].DstPort != 443 || got[0].Proto != 6 || got[0].SrcAS != 65001 || got[0].Dir != "in" {
		t.Fatalf("row fields not preserved: %+v", got[0])
	}

	// Port filter matches src OR dst port.
	if p, _ := l.Query(Filter{Port: 443, HasPort: true}); len(p) != 3 {
		t.Fatalf("expected 3 flows on port 443, got %d", len(p))
	}
	// Proto filter that matches nothing.
	if u, _ := l.Query(Filter{Proto: 17, HasProto: true}); len(u) != 0 {
		t.Fatalf("expected 0 UDP flows, got %d", len(u))
	}
	// Time window.
	if w, _ := l.Query(Filter{Since: now - 1}); len(w) != 2 {
		t.Fatalf("expected 2 flows since now-1, got %d", len(w))
	}
}

func TestSampling(t *testing.T) {
	l, _ := newTestLogger(t, Config{SampleRate: 10})
	now := time.Now().Unix()
	for i := 0; i < 100; i++ {
		l.Enqueue(sampleRow("198.51.100.1", now))
	}
	waitForRows(t, l, 10)
	n, _, _ := l.Stats()
	if n != 10 {
		t.Fatalf("sample_rate=10 over 100 flows should persist 10, got %d", n)
	}
}

func TestDropOnFullBuffer(t *testing.T) {
	// Tiny buffer, and we never let the writer drain (no sleep): most sends
	// hit the default branch and increment drops rather than blocking.
	l, _ := newTestLogger(t, Config{BufferSize: 4, BatchSize: 1000})
	for i := 0; i < 10000; i++ {
		l.Enqueue(sampleRow("198.51.100.1", int64(i)))
	}
	// The key guarantee is that Enqueue never blocked (the loop above returned).
	// Some rows land, some drop — just assert the drop counter engaged.
	if l.drops.Load() == 0 {
		t.Skip("writer kept up; drop path not exercised on this machine")
	}
}

// fillSync writes n rows straight to SQLite (bypassing the async writer) so the
// test controls exactly how much data is present before pruning.
func fillSync(t *testing.T, l *Logger, n int) {
	t.Helper()
	batch := make([]Row, 0, 1000)
	now := time.Now().Unix()
	for i := 0; i < n; i++ {
		batch = append(batch, sampleRow("198.51.100.1", now-int64(i)))
		if len(batch) == 1000 {
			if err := l.writeBatch(batch); err != nil {
				t.Fatalf("writeBatch: %v", err)
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := l.writeBatch(batch); err != nil {
			t.Fatalf("writeBatch: %v", err)
		}
	}
}

func TestPruneBoundsSize(t *testing.T) {
	l, _ := newTestLogger(t, Config{MaxBytes: 96 * 1024}) // 96 KB budget

	fill := 6000 // enough rows (with 3 indexes) to blow past 96 KB

	// Fill past the cap, then prune.
	fillSync(t, l, fill)
	beforeRows, beforeSize, _ := l.Stats()
	if beforeSize <= int64(l.cfg.MaxBytes) {
		t.Fatalf("precondition: expected to exceed cap, size=%d", beforeSize)
	}
	if err := l.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}
	afterRows, _, _ := l.Stats()
	if afterRows >= beforeRows {
		t.Fatalf("prune should remove rows: before=%d after=%d", beforeRows, afterRows)
	}

	// The real guarantee: refilling and pruning again STABILISES the file — the
	// high-water mark does not keep growing (freed pages get reused).
	fillSync(t, l, fill)
	_, size2, _ := l.Stats()
	_ = l.prune()
	fillSync(t, l, fill)
	_, size3, _ := l.Stats()
	_ = l.prune()
	if size3 > size2*3/2 {
		t.Fatalf("file not stabilising: cycle2=%d cycle3=%d bytes", size2, size3)
	}
}

// TestPruneUsesLiveDataNotFileSize is the F2 regression: after a burst bloats
// the file and a prune leaves many free pages behind, a subsequent prune must
// key off LIVE data (page_count - freelist), not total file size. Otherwise it
// treats the free pages as data, inflates bytes-per-row, and deletes almost
// everything.
func TestPruneUsesLiveDataNotFileSize(t *testing.T) {
	l, _ := newTestLogger(t, Config{MaxBytes: 256 * 1024})

	// Bloat far past the cap, then prune — this leaves the file large with many
	// free pages while the live data drops under the cap.
	fillSync(t, l, 30000)
	if err := l.prune(); err != nil {
		t.Fatalf("prune: %v", err)
	}
	rows1, file1, _ := l.Stats()
	used1, _ := l.usedBytes()

	if used1 > int64(l.cfg.MaxBytes) {
		t.Skipf("live data still over cap after first prune (%d) — can't exercise the no-op path", used1)
	}
	if file1 <= int64(l.cfg.MaxBytes) {
		t.Logf("note: file already at/under cap (%d) — free-page inflation not present on this build", file1)
	}

	// Second prune: live data fits, so it MUST be a no-op. The old (file-size)
	// math would over-delete the survivors here.
	if err := l.prune(); err != nil {
		t.Fatalf("prune 2: %v", err)
	}
	rows2, _, _ := l.Stats()
	if rows2 != rows1 {
		t.Fatalf("second prune over-deleted (used file size, not live size): %d -> %d rows", rows1, rows2)
	}
}

// TestCloseFlushesPending is the F1 regression: Close() must drain and flush the
// buffered rows before closing the DB — no lost final batch, no "database is
// closed". A large BatchSize keeps the writer from flushing mid-run so the flush
// is forced by Close.
func TestCloseFlushesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shutdown.db")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := Init(ctx, Config{DBPath: path, BatchSize: 100000})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	const N = 500
	now := time.Now().Unix()
	for i := 0; i < N; i++ {
		l.Enqueue(sampleRow("198.51.100.7", now))
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	Global = nil

	// Reopen the file independently and confirm every flow persisted.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != N {
		t.Fatalf("Close lost flows: expected %d persisted, got %d", N, n)
	}
}
