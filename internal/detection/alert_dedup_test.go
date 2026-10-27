package detection

import (
	"testing"
	"time"
)

func TestAlertDeduperIncidentLifecycle(t *testing.T) {
	d := newAlertDeduper(10 * time.Minute)
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	// First match of an incident is logged.
	if ok, sup := d.observe("scan", "1.2.3.4", t0); !ok || sup != 0 {
		t.Fatalf("first match: log=%v suppressed=%d; want true, 0", ok, sup)
	}
	// The next 599 per-second matches inside the cooldown are swallowed.
	for i := 1; i < 600; i++ {
		if ok, _ := d.observe("scan", "1.2.3.4", t0.Add(time.Duration(i)*time.Second)); ok {
			t.Fatalf("match at +%ds was logged inside the cooldown", i)
		}
	}
	// Another source / rule is its own incident.
	if ok, _ := d.observe("scan", "5.6.7.8", t0.Add(time.Second)); !ok {
		t.Fatal("different source must be logged")
	}
	if ok, _ := d.observe("other", "1.2.3.4", t0.Add(time.Second)); !ok {
		t.Fatal("different rule must be logged")
	}
	// Still matching after a cooldown: logged again, carrying the suppressed count.
	if ok, sup := d.observe("scan", "1.2.3.4", t0.Add(10*time.Minute)); !ok || sup != 599 {
		t.Fatalf("after cooldown: log=%v suppressed=%d; want true, 599", ok, sup)
	}
	d.observe("scan", "1.2.3.4", t0.Add(10*time.Minute+time.Second)) // one more, unlogged

	// The two one-off incidents (last seen at +1s) have been quiet for a
	// cooldown at +15m; scan/1.2.3.4 (last seen at +10m1s) has not.
	if ended := d.expire(t0.Add(15 * time.Minute)); len(ended) != 2 {
		t.Fatalf("expire at +15m ended %+v; want only the 2 quiet incidents", ended)
	}
	ended := d.expire(t0.Add(21 * time.Minute))
	if len(ended) != 1 || ended[0].Rule != "scan" || ended[0].Src != "1.2.3.4" {
		t.Fatalf("expire at +21m ended %+v; want scan/1.2.3.4", ended)
	}
	if inc := ended[0]; inc.Matches != 602 || inc.Suppressed != 1 || !inc.FirstSeen.Equal(t0) {
		t.Fatalf("scan incident = %+v; want 602 matches, 1 unlogged, first=t0", inc)
	}
	// Forgotten: the next match starts a fresh incident.
	if ok, sup := d.observe("scan", "1.2.3.4", t0.Add(30*time.Minute)); !ok || sup != 0 {
		t.Fatalf("after end: log=%v suppressed=%d; want a fresh incident", ok, sup)
	}
}

func TestAlertDeduperDisabled(t *testing.T) {
	var nilDedup *alertDeduper // engine without SetAlertCooldown
	for _, d := range []*alertDeduper{nilDedup, newAlertDeduper(0), newAlertDeduper(-time.Second)} {
		now := time.Now()
		for i := 0; i < 3; i++ {
			if ok, _ := d.observe("r", "1.1.1.1", now); !ok {
				t.Fatalf("disabled deduper (%v) suppressed a match", d)
			}
		}
		if ended := d.expire(now.Add(time.Hour)); ended != nil {
			t.Fatalf("disabled deduper reported incidents: %v", ended)
		}
	}
}

func TestMatchTCPFlagsSynOnly(t *testing.T) {
	cases := []struct {
		flags uint8
		want  bool
	}{
		{0x02, true},  // SYN: scan probe
		{0x12, false}, // SYN+ACK
		{0x10, false}, // ACK: reply traffic
		{0x1b, false}, // FIN+SYN+PSH+ACK: a whole client connection, aggregated
		{0x00, false},
	}
	for _, c := range cases {
		if got := matchTCPFlags(c.flags, "syn-only"); got != c.want {
			t.Errorf("matchTCPFlags(%#x, SYN-ONLY) = %v; want %v", c.flags, got, c.want)
		}
	}
}
