package detection

import (
	"errors"
	"net"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// setProtected swaps the in-memory protection list for the test's duration.
func setProtected(t *testing.T, ips []string, cidrs []string) {
	t.Helper()
	protectedLock.Lock()
	oldIPs, oldPrefixes := protectedIPs, protectedPrefixes
	protectedIPs = map[string]struct{}{}
	protectedPrefixes = nil
	for _, ip := range ips {
		protectedIPs[ip] = struct{}{}
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad cidr %q", c)
		}
		protectedPrefixes = append(protectedPrefixes, n)
	}
	protectedLock.Unlock()
	t.Cleanup(func() {
		protectedLock.Lock()
		protectedIPs, protectedPrefixes = oldIPs, oldPrefixes
		protectedLock.Unlock()
	})
}

type fakeReporter struct {
	mu        sync.Mutex
	unblocked []string
}

func (f *fakeReporter) ReportBlock(ip, description string, ttlSec int) error { return nil }
func (f *fakeReporter) ReportUnblock(ip, source, why string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unblocked = append(f.unblocked, ip)
	return nil
}

func TestWithdrawProtectedBlackholes(t *testing.T) {
	db := openBlackholeTestDB(t)
	const permanent = "9999-12-31T00:00:00Z"
	// The 79.129.12.159 case: a permanent blackhole announced before the
	// exclusion was added; plus one covered by an excluded CIDR, one that is
	// not protected, and one whose BGP withdraw fails.
	insertBlackholeRow(t, db, "79.129.12.159/32", permanent, "generic_scanner")
	insertBlackholeRow(t, db, "203.0.113.7/32", permanent, "r")
	insertBlackholeRow(t, db, "198.51.100.1/32", permanent, "r")
	insertBlackholeRow(t, db, "203.0.113.9/32", permanent, "r")
	setProtected(t, []string{"79.129.12.159"}, []string{"203.0.113.0/24"})

	var withdrawn []string
	rep := &fakeReporter{}
	n, err := withdrawProtectedBlackholes(db, rep, func(prefix string) error {
		if prefix == "203.0.113.9/32" {
			return errors.New("bgp down")
		}
		withdrawn = append(withdrawn, prefix)
		return nil
	})
	if err != nil {
		t.Fatalf("withdrawProtectedBlackholes: %v", err)
	}
	if n != 2 {
		t.Fatalf("withdrew %d; want 2", n)
	}
	sort.Strings(withdrawn)
	if want := []string{"203.0.113.7/32", "79.129.12.159/32"}; !reflect.DeepEqual(withdrawn, want) {
		t.Fatalf("withdrawn = %v; want %v", withdrawn, want)
	}
	sort.Strings(rep.unblocked)
	if want := []string{"203.0.113.7", "79.129.12.159"}; !reflect.DeepEqual(rep.unblocked, want) {
		t.Fatalf("CFM unblocked = %v; want %v", rep.unblocked, want)
	}

	// The unprotected row stays, and so does the failed one (retried next reload).
	rows, err := db.Query(`SELECT prefix FROM blackholes ORDER BY prefix`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var left []string
	for rows.Next() {
		var p string
		_ = rows.Scan(&p)
		left = append(left, p)
	}
	rows.Close()
	if want := []string{"198.51.100.1/32", "203.0.113.9/32"}; !reflect.DeepEqual(left, want) {
		t.Fatalf("remaining blackholes = %v; want %v", left, want)
	}
	waitForEvents(t, db, BHEventWithdrawn, 2)

	// The next reload retries the failed one (nil reporter = CFM off), then
	// there is nothing left to do.
	// 203.0.113.9's withdraw now succeeds.
	if n, err := withdrawProtectedBlackholes(db, nil, func(string) error { return nil }); err != nil || n != 1 {
		t.Fatalf("second pass: n=%d err=%v; want 1, nil", n, err)
	}
	if n, _ := withdrawProtectedBlackholes(db, nil, func(string) error { return nil }); n != 0 {
		t.Fatalf("third pass withdrew %d; want 0", n)
	}
}

func TestRestoreSkipsProtectedBlackholes(t *testing.T) {
	db := openBlackholeTestDB(t)
	insertBlackholeRow(t, db, "79.129.12.159/32", "9999-12-31T00:00:00Z", "generic_scanner")
	insertBlackholeRow(t, db, "198.51.100.1/32", "9999-12-31T00:00:00Z", "generic_scanner")
	setProtected(t, []string{"79.129.12.159"}, nil)

	var announced []string
	err := restoreActiveBlackholes(db, nil, func(prefix, _ string, _ []string, _ []uint32) error {
		announced = append(announced, prefix)
		return nil
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if want := []string{"198.51.100.1/32"}; !reflect.DeepEqual(announced, want) {
		t.Fatalf("restored %v; want %v", announced, want)
	}
}

func TestFeedProtectionWithdrawsAndSurvivesExclusionReload(t *testing.T) {
	db := openBlackholeTestDB(t)
	if err := InitExcludesTable(db); err != nil {
		t.Fatal(err)
	}
	insertBlackholeRow(t, db, "104.16.5.9/32", "9999-12-31T00:00:00Z", "web_slow_scan") // Cloudflare edge
	insertBlackholeRow(t, db, "198.51.100.1/32", "9999-12-31T00:00:00Z", "web_slow_scan")
	setProtected(t, nil, nil)
	_, cf, _ := net.ParseCIDR("104.16.0.0/13")
	SetFeedProtected("cloudflare", []*net.IPNet{cf})
	t.Cleanup(func() { SetFeedProtected("cloudflare", nil) })

	// An exclusions reload replaces only the exclusions, not the feed.
	if err := LoadProtectedFromDB(db); err != nil {
		t.Fatal(err)
	}
	if !IsProtected("104.16.5.9") || ProtectingFeed("104.16.5.9") != "cloudflare" || IsProtected("198.51.100.1") {
		t.Fatal("feed coverage wrong after exclusions reload")
	}
	if ok, why := ShouldExecuteBlackhole("web_slow_scan", "104.16.5.9"); ok || why != "protected (feed cloudflare)" {
		t.Fatalf("ShouldExecuteBlackhole = %v %q", ok, why)
	}

	rep := &fakeReporter{}
	n, err := withdrawProtectedBlackholes(db, rep, func(string) error { return nil })
	if err != nil || n != 1 || len(rep.unblocked) != 1 || rep.unblocked[0] != "104.16.5.9" {
		t.Fatalf("withdraw n=%d err=%v unblocked=%v", n, err, rep.unblocked)
	}
	waitForEvents(t, db, BHEventWithdrawn, 1)
	var reason string
	if err := db.QueryRow(`SELECT reason FROM blackhole_events WHERE event = ?`, BHEventWithdrawn).Scan(&reason); err != nil ||
		reason != "covered by protection feed cloudflare" {
		t.Fatalf("reason = %q, %v", reason, err)
	}

	// Clearing the feed lifts the protection.
	SetFeedProtected("cloudflare", nil)
	if IsProtected("104.16.5.9") {
		t.Fatal("still protected after feed cleared")
	}
}

func TestFeedSkipThrottle(t *testing.T) {
	SetFeedSkipInterval(24 * time.Hour)
	t.Cleanup(func() { SetFeedSkipInterval(24 * time.Hour) })
	now := time.Now()
	if !recordFeedSkip("104.16.0.77", now) {
		t.Fatal("first skip not recorded")
	}
	if recordFeedSkip("104.16.0.77", now.Add(time.Hour)) {
		t.Fatal("repeat within interval recorded")
	}
	if !recordFeedSkip("104.16.0.77", now.Add(25*time.Hour)) {
		t.Fatal("skip after interval not recorded")
	}
	SetFeedSkipInterval(0)
	if !recordFeedSkip("104.16.0.77", now.Add(25*time.Hour)) {
		t.Fatal("interval <= 0 must record every time")
	}
}
