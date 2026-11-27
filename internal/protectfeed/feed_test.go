package protectfeed

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// cfDoc renders a Cloudflare /client/v4/ips answer.
func cfDoc(v4, v6 []string) string {
	q := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return `"` + strings.Join(l, `","`) + `"`
	}
	return fmt.Sprintf(`{"success":true,"result":{"ipv4_cidrs":[%s],"ipv6_cidrs":[%s],"etag":"x"}}`, q(v4), q(v6))
}

var cfV4 = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"}
var cfV6 = []string{"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}

func TestParseCloudflare(t *testing.T) {
	p, err := Parse(FormatCloudflare, []byte(cfDoc(cfV4, cfV6)), Limits{})
	if err != nil || len(p) != 22 {
		t.Fatalf("Parse = %d prefixes, %v; want 22", len(p), err)
	}
	if _, err := Parse(FormatCloudflare, []byte(`{"success":false}`), Limits{}); err == nil {
		t.Fatal("unsuccessful answer accepted")
	}
	// One bad entry refuses the whole answer.
	if _, err := Parse(FormatCloudflare, []byte(cfDoc(append([]string{"10.0.0.0/8"}, cfV4...), cfV6)), Limits{}); err == nil {
		t.Fatal("private range accepted")
	}
}

func TestNormalizePrefix(t *testing.T) {
	for _, bad := range []string{
		"104.16.0.1/13",      // host bits
		"104.16.0.1",         // not a CIDR
		"8.0.0.0/8",          // broader than /12
		"2400::/16",          // broader than /28
		"192.168.0.0/16",     // private
		"100.64.0.0/10",      // CGNAT (also too broad)
		"100.64.0.0/16",      // CGNAT
		"127.0.0.0/16",       // loopback
		"224.0.0.0/16",       // multicast
		"198.51.100.0/24",    // documentation
		"2002:c000::/32",     // 6to4
		"::ffff:1.2.3.0/120", // v4-mapped
		"fc00::/32",          // ULA
	} {
		if _, err := NormalizePrefix(bad, Limits{}); err == nil {
			t.Errorf("NormalizePrefix(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"104.16.0.0/13", "2a06:98c0::/29", "1.1.1.0/24", "2606:4700::/32"} {
		if _, err := NormalizePrefix(ok, Limits{}); err != nil {
			t.Errorf("NormalizePrefix(%q): %v", ok, err)
		}
	}
}

func mustParse(t *testing.T, v4, v6 []string) []netip.Prefix {
	t.Helper()
	p, err := Parse(FormatCloudflare, []byte(cfDoc(v4, v6)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckGuards(t *testing.T) {
	f := Feed{Name: "cloudflare", MinPrefixes: 8, MaxPrefixes: 200}
	full := mustParse(t, cfV4, cfV6)
	if err := Check(f, full, nil, Limits{}); err != nil {
		t.Fatalf("first answer refused: %v", err)
	}
	if err := Check(f, mustParse(t, cfV4[:3], cfV6[:2]), nil, Limits{}); err == nil {
		t.Fatal("count below min accepted")
	}
	// Partial answer: v4 count halves.
	if err := Check(f, mustParse(t, cfV4[:6], cfV6), full, Limits{}); err == nil {
		t.Fatal("count shrink accepted")
	}
	// Space collapse: drop the big /13s and /14 while keeping the count up.
	small := []string{}
	for _, c := range cfV4 {
		if !strings.HasSuffix(c, "/13") && !strings.HasSuffix(c, "/14") && !strings.HasSuffix(c, "/15") {
			small = append(small, c)
		}
	}
	if err := Check(f, mustParse(t, small, cfV6), full, Limits{}); err == nil || !strings.Contains(err.Error(), "shrank") {
		t.Fatalf("space shrink: %v", err)
	}
	// Poisoned: two /12s added more than double the v4 space.
	if err := Check(f, mustParse(t, append([]string{"20.0.0.0/12", "24.0.0.0/12"}, cfV4...), cfV6), full, Limits{}); err == nil || !strings.Contains(err.Error(), "grew") {
		t.Fatalf("space growth: %v", err)
	}
	// A real small change passes.
	if err := Check(f, mustParse(t, append([]string{"131.0.76.0/22"}, cfV4...), cfV6), full, Limits{}); err != nil {
		t.Fatalf("small change refused: %v", err)
	}
	// Space ignores more-specifics of a listed prefix.
	a, _ := Space(mustParse(t, []string{"104.16.0.0/13", "104.16.0.0/16"}, nil))
	if a != 1<<19 {
		t.Fatalf("Space = %d; want %d", a, 1<<19)
	}
}

func TestManagerCacheAndRefresh(t *testing.T) {
	var mu sync.Mutex
	body := cfDoc(cfV4, cfV6)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	applied := map[string][]*net.IPNet{}
	apply := func(name string, nets []*net.IPNet) { applied[name] = nets }
	f := Feed{Name: "cloudflare", URL: srv.URL, Format: FormatCloudflare, MinPrefixes: 8, MaxPrefixes: 200}

	m := New([]Feed{f}, dir, 0, Limits{}, apply)
	m.LoadCache() // nothing cached yet
	if len(applied) != 0 {
		t.Fatal("applied without cache")
	}
	m.Refresh(context.Background(), f)
	if len(applied["cloudflare"]) != 22 {
		t.Fatalf("applied %d; want 22", len(applied["cloudflare"]))
	}
	st := m.Statuses()[0]
	if st.Prefixes != 22 || st.IPv4 != 15 || st.IPv6 != 7 || st.LastError != "" || st.FromCache {
		t.Fatalf("status = %+v", st)
	}
	cache, err := os.ReadFile(filepath.Join(dir, "cloudflare.txt"))
	if err != nil || !strings.Contains(string(cache), "104.16.0.0/13") {
		t.Fatalf("cache = %q, %v", cache, err)
	}

	// A truncated answer is refused and the active list stays.
	mu.Lock()
	body = cfDoc(cfV4[:2], cfV6[:1])
	mu.Unlock()
	m.Refresh(context.Background(), f)
	if st := m.Statuses()[0]; st.Prefixes != 22 || st.LastError == "" {
		t.Fatalf("after bad answer: %+v", st)
	}
	if len(applied["cloudflare"]) != 22 {
		t.Fatal("bad answer applied")
	}

	// A restart without network comes up from the cache, and is not stale.
	srv.Close()
	applied = map[string][]*net.IPNet{}
	m2 := New([]Feed{f}, dir, 0, Limits{}, apply)
	m2.LoadCache()
	if len(applied["cloudflare"]) != 22 || !m2.Statuses()[0].FromCache || m2.stale(f) {
		t.Fatalf("cache restart: applied=%d status=%+v", len(applied["cloudflare"]), m2.Statuses()[0])
	}
}

func TestFeedValidate(t *testing.T) {
	good := Feed{Name: "cloudflare", URL: "https://api.cloudflare.com/client/v4/ips", Format: FormatCloudflare}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []Feed{
		{Name: "../etc", URL: good.URL, Format: FormatText},
		{Name: "x", URL: "http://example.com", Format: FormatText},
		{Name: "x", URL: good.URL, Format: "xml"},
	} {
		if f.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", f)
		}
	}
}

func TestLimitsConfigurable(t *testing.T) {
	// A stricter prefix bound refuses Cloudflare's /13s.
	if _, err := NormalizePrefix("104.16.0.0/13", Limits{MinIPv4PrefixLen: 16}); err == nil {
		t.Fatal("/13 accepted with min_ipv4_prefixlen 16")
	}
	// A looser growth factor accepts what the default refuses.
	f := Feed{Name: "cloudflare", MinPrefixes: 8, MaxPrefixes: 200}
	full := mustParse(t, cfV4, cfV6)
	grown := mustParse(t, append([]string{"20.0.0.0/12", "24.0.0.0/12"}, cfV4...), cfV6)
	if err := Check(f, grown, full, Limits{MaxSpaceGrowth: 4}); err != nil {
		t.Fatalf("growth within factor 4 refused: %v", err)
	}
	// Overflow-safe clamps.
	if l := (Limits{MinIPv4PrefixLen: 1, MinIPv6PrefixLen: 2}).withDefaults(); l.MinIPv4PrefixLen != 8 || l.MinIPv6PrefixLen != 16 {
		t.Fatalf("clamp = %+v", l)
	}
}

func TestRetryBackoff(t *testing.T) {
	first, max := 5*time.Minute, 24*time.Hour
	var d time.Duration
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute}
	for _, w := range want {
		if d = retryAfter(d, first, max); d != w {
			t.Fatalf("retryAfter = %s; want %s", d, w)
		}
	}
	if d = retryAfter(20*time.Hour, first, max); d != max {
		t.Fatalf("cap = %s; want %s", d, max)
	}
}

// A first fetch that fails is retried after RetryMin, not after the refresh
// interval; cancelling during a refresh records no error.
func TestRunRetriesFailedFirstFetch(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, cfDoc(cfV4, cfV6))
	}))
	defer srv.Close()

	var amu sync.Mutex
	got := 0
	f := Feed{Name: "cloudflare", URL: srv.URL, Format: FormatCloudflare, MinPrefixes: 8, MaxPrefixes: 200}
	m := New([]Feed{f}, t.TempDir(), time.Hour, Limits{RetryMin: 20 * time.Millisecond}, func(_ string, nets []*net.IPNet) {
		amu.Lock()
		got = len(nets)
		amu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		amu.Lock()
		g := got
		amu.Unlock()
		if g == 22 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not applied after retry (calls=%d)", calls)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := m.Statuses()[0]; st.LastError != "" {
		t.Fatalf("error not cleared after successful retry: %q", st.LastError)
	}
	cancel()
	<-done

	// A cancelled refresh is not a feed failure.
	if err := m.Refresh(ctx, f); err == nil {
		t.Fatal("cancelled refresh returned nil")
	}
	if st := m.Statuses()[0]; st.LastError != "" {
		t.Fatalf("cancel recorded as error: %q", st.LastError)
	}
}
