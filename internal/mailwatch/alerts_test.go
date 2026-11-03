package mailwatch

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func testAlertCfg() AlertConfig {
	return AlertConfig{Enabled: true, LearningPeriod: 7 * 24 * time.Hour, NewSenderMinDsts: 10,
		SpikeMinDsts: 50, SpikeFactor: 5, BaselineWindow: 7 * 24 * time.Hour, Cooldown: time.Hour}
}

// burst observes n distinct destinations on :25 from src.
func burst(tr *Tracker, src string, n int) {
	for i := 0; i < n; i++ {
		tr.Observe(Flow{Src: src, Dst: fmt.Sprintf("198.51.%d.%d", i/250, i%250), DstPort: 25, DstAS: 15169, DstASName: "Google LLC"})
	}
}

func countAlerts(t *testing.T, db *sql.DB, kind string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM mail_egress_alerts WHERE kind = ?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNewSenderAlertNeedsLearnedHistory(t *testing.T) {
	db := openTestDB(t)
	var got []Alert
	tr := New(Config{Ports: []uint16{25}, Bucket: 5 * time.Minute})
	tr.SetAlerts(testAlertCfg(), func(a Alert) { got = append(got, a) })
	now := time.Now().Truncate(5 * time.Minute)

	// Fresh install: everyone is "new", but no history yet → no alert.
	burst(tr, "84.54.49.200", 20)
	tr.flush(db, now)
	if len(got) != 0 {
		t.Fatalf("alerted during learning: %+v", got)
	}

	// History is 8 days old: an unknown sender with 20 dsts alerts once; a
	// known sender with the same volume does not.
	if _, err := db.Exec(`UPDATE mail_egress_senders SET first_seen = ?`, now.Add(-8*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	burst(tr, "84.54.49.205", 20)
	burst(tr, "84.54.49.200", 20)
	burst(tr, "84.54.49.206", 5) // new but below new_sender_min_dsts
	tr.flush(db, now.Add(5*time.Minute))
	if len(got) != 1 || got[0].Kind != AlertNewSender || got[0].IP != "84.54.49.205" || got[0].UniqDsts != 20 {
		t.Fatalf("alerts = %+v; want one new_sender for .205", got)
	}
	if countAlerts(t, db, AlertNewSender) != 1 {
		t.Fatal("alert not stored")
	}

	// Next bucket .205 is known: no second new_sender.
	burst(tr, "84.54.49.205", 20)
	tr.flush(db, now.Add(10*time.Minute))
	if len(got) != 1 {
		t.Fatalf("new_sender repeated: %+v", got)
	}
}

func TestSpikeAlertAgainstOwnBaseline(t *testing.T) {
	db := openTestDB(t)
	var got []Alert
	tr := New(Config{Ports: []uint16{25}, Bucket: 5 * time.Minute})
	tr.SetAlerts(testAlertCfg(), func(a Alert) { got = append(got, a) })
	base := time.Now().Truncate(5 * time.Minute).Add(-24 * time.Hour)

	// A busy relay: 20 distinct MXs per bucket for 40 buckets (p95 = 20,
	// threshold = 100).
	for i := 0; i < 40; i++ {
		burst(tr, "84.54.49.25", 20)
		tr.flush(db, base.Add(time.Duration(i)*5*time.Minute))
	}
	// 80 dsts: above the 50 floor but not 5× its p95 → no alert.
	burst(tr, "84.54.49.25", 80)
	// A quiet host jumping to 60: no history → threshold is the floor (50).
	burst(tr, "84.54.49.203", 60)
	t1 := base.Add(40 * 5 * time.Minute)
	tr.flush(db, t1)
	if len(got) != 1 || got[0].IP != "84.54.49.203" || got[0].Kind != AlertSpike || got[0].Threshold != 50 {
		t.Fatalf("alerts = %+v; want one spike for .203 at threshold 50", got)
	}

	// 120 dsts from the relay: >= 5 × 20 → spike, baseline reported.
	burst(tr, "84.54.49.25", 120)
	tr.flush(db, t1.Add(5*time.Minute))
	if len(got) != 2 || got[1].IP != "84.54.49.25" || got[1].Baseline != 20 || got[1].Threshold != 100 {
		t.Fatalf("relay spike = %+v", got[len(got)-1])
	}

	// Cooldown: a repeat within the hour is suppressed, after it fires again.
	burst(tr, "84.54.49.203", 60)
	tr.flush(db, t1.Add(10*time.Minute))
	if len(got) != 2 {
		t.Fatalf("cooldown not applied: %+v", got)
	}
	// (A bucket's start is set by the previous flush; production flushes every
	// boundary, so advance the clock with an empty one.)
	tr.flush(db, t1.Add(70*time.Minute))
	burst(tr, "84.54.49.203", 400)
	tr.flush(db, t1.Add(75*time.Minute))
	if len(got) != 3 || got[2].Severity != "critical" {
		t.Fatalf("after cooldown = %+v; want critical spike (400 >= 4×50)", got[len(got)-1])
	}

	alerts, err := Alerts(db, base, "84.54.49.203", 0)
	if err != nil || len(alerts) != 2 || alerts[0].UniqDsts != 400 || len(alerts[0].TopASNs) == 0 {
		t.Fatalf("Alerts(.203) = %+v, %v", alerts, err)
	}
	if err := PruneAlerts(db, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := countAlerts(t, db, AlertSpike); n != 0 {
		t.Fatalf("prune left %d alerts", n)
	}
}
