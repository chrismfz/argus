package mailwatch

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "mw.db")+
		"?mode=rwc&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := InitSchema(db); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

func TestObserveFlushAndQuery(t *testing.T) {
	db := openTestDB(t)
	tr := New(Config{Ports: []uint16{25, 587}, Bucket: 5 * time.Minute, MaxDsts: 30, TopN: 3})

	// A burst: 40 distinct MXs on :25, the first one hit 5 times.
	for i := 0; i < 40; i++ {
		tr.Observe(Flow{Src: "84.54.49.205", Dst: fmt.Sprintf("198.51.100.%d", i), DstPort: 25,
			DstAS: uint32(64500 + i%4), DstASName: "AS-TEST", Bytes: 1000, Packets: 10})
	}
	for i := 0; i < 4; i++ {
		tr.Observe(Flow{Src: "84.54.49.205", Dst: "198.51.100.0", DstPort: 25, DstAS: 64500, Bytes: 1000, Packets: 10})
	}
	// A normal relay on :587, and a non-mail port that must be ignored.
	tr.Observe(Flow{Src: "84.54.49.200", Dst: "203.0.113.5", DstPort: 587, DstAS: 64510, Bytes: 500, Packets: 5})
	tr.Observe(Flow{Src: "84.54.49.200", Dst: "203.0.113.5", DstPort: 443, Bytes: 500, Packets: 5})
	if tr.WantsPort(443) || !tr.WantsPort(25) {
		t.Fatal("WantsPort wrong")
	}

	now := time.Now()
	tr.flush(db, now)

	senders, err := Senders(db, now.Add(-time.Hour), 5*time.Minute, 0)
	if err != nil {
		t.Fatalf("Senders: %v", err)
	}
	if len(senders) != 2 || senders[0].IP != "84.54.49.205" {
		t.Fatalf("senders = %+v", senders)
	}
	s := senders[0]
	if s.Flows != 44 || s.Bytes != 44000 {
		t.Fatalf("flows/bytes = %d/%d; want 44/44000", s.Flows, s.Bytes)
	}
	// MaxDsts=30 caps distinct tracking and marks the bucket as a lower bound.
	if s.PeakDsts != 30 || !s.Capped {
		t.Fatalf("peak=%d capped=%v; want 30, true", s.PeakDsts, s.Capped)
	}
	if s.FirstSeen == 0 || s.TotalFlows != 44 || s.MaxDstsEver != 30 {
		t.Fatalf("memory row = %+v", s)
	}
	if len(senders[1].Ports) != 1 || senders[1].Ports[0] != 587 || senders[1].Flows != 1 {
		t.Fatalf("relay sender = %+v (443 must be ignored)", senders[1])
	}

	h, err := History(db, "84.54.49.205", now.Add(-time.Hour), 3)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if !h.Known || len(h.Buckets) != 1 || len(h.TopDsts) != 3 || h.TopDsts[0].IP != "198.51.100.0" || h.TopDsts[0].Flows != 5 {
		t.Fatalf("history = %+v", h)
	}
	if len(h.TopASNs) != 3 || h.TopASNs[0].ASN != 64500 {
		t.Fatalf("top asns = %+v", h.TopASNs)
	}

	// Second bucket: the memory row accumulates, first_seen stays.
	first := s.FirstSeen
	tr.Observe(Flow{Src: "84.54.49.205", Dst: "198.51.100.1", DstPort: 25, Bytes: 1, Packets: 1})
	tr.flush(db, now.Add(5*time.Minute))
	h, _ = History(db, "84.54.49.205", now.Add(-time.Hour), 3)
	if h.TotalFlows != 45 || h.FirstSeen != first || h.MaxDstsEver != 30 {
		t.Fatalf("after 2nd bucket: %+v", h)
	}

	// Unknown IP: not an error.
	if h, err := History(db, "192.0.2.1", now.Add(-time.Hour), 3); err != nil || h.Known {
		t.Fatalf("unknown ip: %+v %v", h, err)
	}
}

func TestMaxSendersDropsNewKeys(t *testing.T) {
	tr := New(Config{Ports: []uint16{25}, MaxSenders: 2})
	for i := 0; i < 5; i++ {
		tr.Observe(Flow{Src: fmt.Sprintf("10.0.0.%d", i), Dst: "198.51.100.1", DstPort: 25})
	}
	tr.Observe(Flow{Src: "10.0.0.0", Dst: "198.51.100.2", DstPort: 25}) // existing key still counts
	_, cur, dropped := tr.swap(time.Now())
	if len(cur) != 2 || dropped != 3 {
		t.Fatalf("keys=%d dropped=%d; want 2, 3", len(cur), dropped)
	}
	if a := cur[key{"10.0.0.0", 25}]; a == nil || a.flows != 2 {
		t.Fatalf("existing key not updated: %+v", a)
	}
}

func TestPrune(t *testing.T) {
	db := openTestDB(t)
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	recent := time.Now().Unix()
	for _, ts := range []int64{old, recent} {
		if _, err := db.Exec(`INSERT INTO mail_egress_buckets (ts, src_ip, port, flows, packets, bytes, uniq_dsts, uniq_asns)
			VALUES (?, '84.54.49.205', 25, 1, 1, 1, 1, 1)`, ts); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`INSERT INTO mail_egress_senders (src_ip, first_seen, last_seen) VALUES ('a', ?, ?), ('b', ?, ?)`, old, old, old, recent)

	// Negative = keep forever.
	if err := Prune(db, -1, -1); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM mail_egress_buckets`).Scan(&n)
	if n != 2 {
		t.Fatalf("keep-forever pruned buckets: %d left", n)
	}
	if err := Prune(db, 30*24*time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT count(*) FROM mail_egress_buckets`).Scan(&n)
	if n != 1 {
		t.Fatalf("buckets left = %d; want 1", n)
	}
	db.QueryRow(`SELECT count(*) FROM mail_egress_senders`).Scan(&n)
	if n != 1 {
		t.Fatalf("senders left = %d; want 1", n)
	}
}
