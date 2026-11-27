// Package protectfeed keeps published network ranges (CDN edges such as
// Cloudflare's) on the detection protection list, refreshed from their
// owner's feed.
//
// A CDN edge talks to many of our IPs on 80/443 on behalf of its visitors, so
// horizontal-scan rules match it. Blackholing an edge never stops an attacker
// (the next request comes from another edge) but breaks every site behind it
// for that edge's visitors. The ranges change rarely, but they do change, so
// they are fetched rather than pasted into the exclusions by hand.
//
// A feed answer is only trusted within bounds (ported from chrismfz/cfm
// scripts/build_trusted_proxies.py): public unicast CIDRs only, none broader
// than /12 (v4) or /28 (v6), a prefix-count window, and a guard against the
// count or covered address space halving or the space doubling compared with
// the last accepted list. A refused or failed fetch keeps the last good list,
// which is cached on disk so a restart without network still protects.
package protectfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Formats a feed can be in.
const (
	FormatCloudflare = "cloudflare" // https://api.cloudflare.com/client/v4/ips
	FormatText       = "text"       // one CIDR per line, '#' comments
)

// Limits bound what a feed answer may contain and how it is fetched. Zero
// fields take DefaultLimits' values (the cfm edge's trusted_proxies bounds).
type Limits struct {
	MinIPv4PrefixLen int           // no prefix broader than this, default 12
	MinIPv6PrefixLen int           // default 28
	MaxSpaceGrowth   float64       // refuse if a family's covered space grows by more than this factor, default 2
	MinShrink        float64       // refuse if a family's count or space falls below this fraction, default 0.5
	FetchTimeout     time.Duration // default 30s
	MaxBodyBytes     int64         // default 1 MiB
	RetryMin         time.Duration // first retry after a failed refresh, doubling up to the refresh interval, default 5m
}

// DefaultLimits are the bounds used when a field is unset.
func DefaultLimits() Limits {
	return Limits{MinIPv4PrefixLen: 12, MinIPv6PrefixLen: 28, MaxSpaceGrowth: 2, MinShrink: 0.5,
		FetchTimeout: 30 * time.Second, MaxBodyBytes: 1 << 20, RetryMin: 5 * time.Minute}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MinIPv4PrefixLen <= 0 {
		l.MinIPv4PrefixLen = d.MinIPv4PrefixLen
	}
	if l.MinIPv6PrefixLen <= 0 {
		l.MinIPv6PrefixLen = d.MinIPv6PrefixLen
	}
	// Space() sums 2^(32-len) / 2^(64-len) in a uint64: keep it from overflowing.
	l.MinIPv4PrefixLen = min(max(l.MinIPv4PrefixLen, 8), 32)
	l.MinIPv6PrefixLen = min(max(l.MinIPv6PrefixLen, 16), 128)
	if l.MaxSpaceGrowth <= 0 {
		l.MaxSpaceGrowth = d.MaxSpaceGrowth
	}
	if l.MinShrink <= 0 {
		l.MinShrink = d.MinShrink
	}
	if l.FetchTimeout <= 0 {
		l.FetchTimeout = d.FetchTimeout
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = d.MaxBodyBytes
	}
	if l.RetryMin <= 0 {
		l.RetryMin = d.RetryMin
	}
	return l
}

// Feed is one configured source.
type Feed struct {
	Name        string
	URL         string
	Format      string
	MinPrefixes int // accepted answer must have at least this many prefixes
	MaxPrefixes int // ... and at most this many
}

var feedName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Validate checks a configured feed: the name becomes a cache file name.
func (f Feed) Validate() error {
	if !feedName.MatchString(f.Name) {
		return fmt.Errorf("feed name %q: want [a-z0-9_-], up to 32 chars", f.Name)
	}
	if !strings.HasPrefix(f.URL, "https://") {
		return fmt.Errorf("feed %s: url must be https", f.Name)
	}
	if f.Format != FormatCloudflare && f.Format != FormatText {
		return fmt.Errorf("feed %s: unknown format %q", f.Name, f.Format)
	}
	return nil
}

// Status is what the API reports per feed.
type Status struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Prefixes    int       `json:"prefixes"`
	IPv4        int       `json:"ipv4"`
	IPv6        int       `json:"ipv6"`
	UpdatedAt   time.Time `json:"updated_at"` // when the active list was accepted (or cache written)
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	FromCache   bool      `json:"from_cache"` // active list came from disk, not a fetch in this run
}

// Manager refreshes the feeds and hands each accepted list to apply.
type Manager struct {
	feeds    []Feed
	cacheDir string
	refresh  time.Duration
	limits   Limits
	client   *http.Client
	apply    func(name string, nets []*net.IPNet)

	mu     sync.Mutex
	active map[string][]netip.Prefix
	status map[string]*Status
}

// New builds a manager. apply is called with every accepted list (from cache
// or fetch) and must replace that feed's previous list.
func New(feeds []Feed, cacheDir string, refresh time.Duration, limits Limits, apply func(name string, nets []*net.IPNet)) *Manager {
	if refresh <= 0 {
		refresh = 24 * time.Hour
	}
	limits = limits.withDefaults()
	m := &Manager{
		feeds:    feeds,
		cacheDir: cacheDir,
		refresh:  refresh,
		limits:   limits,
		client:   &http.Client{Timeout: limits.FetchTimeout},
		apply:    apply,
		active:   map[string][]netip.Prefix{},
		status:   map[string]*Status{},
	}
	for _, f := range feeds {
		m.status[f.Name] = &Status{Name: f.Name, URL: f.URL}
	}
	return m
}

// LoadCache applies every feed's cached list. Call it before blackholes are
// restored, so a protected range is never re-announced at startup.
func (m *Manager) LoadCache() {
	for _, f := range m.feeds {
		p, mod, err := readCache(m.cachePath(f), m.limits)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("[protectfeed] %s: cache unreadable: %v", f.Name, err)
			}
			continue
		}
		if len(p) == 0 {
			continue
		}
		m.accept(f, p, mod, true)
		log.Printf("[protectfeed] %s: %d prefixes from cache (%s)", f.Name, len(p), mod.Format(time.RFC3339))
	}
}

// Run refreshes each feed now if its cache is missing or older than the
// refresh interval, then every interval, until ctx ends. A failed or refused
// refresh is retried after Limits.RetryMin, doubling up to the interval, so a
// first deploy whose fetch fails is not left unprotected for a whole day.
func (m *Manager) Run(ctx context.Context) {
	next := make(map[string]time.Time, len(m.feeds))
	backoff := make(map[string]time.Duration, len(m.feeds))
	now := time.Now()
	for _, f := range m.feeds {
		next[f.Name] = now
		if !m.stale(f) {
			m.mu.Lock()
			next[f.Name] = m.status[f.Name].UpdatedAt.Add(m.refresh)
			m.mu.Unlock()
		}
	}
	for len(m.feeds) > 0 {
		due := next[m.feeds[0].Name]
		for _, f := range m.feeds[1:] {
			if next[f.Name].Before(due) {
				due = next[f.Name]
			}
		}
		timer := time.NewTimer(time.Until(due))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		now := time.Now()
		for _, f := range m.feeds {
			if next[f.Name].After(now) {
				continue
			}
			if err := m.Refresh(ctx, f); err != nil {
				if ctx.Err() != nil {
					return
				}
				backoff[f.Name] = retryAfter(backoff[f.Name], m.limits.RetryMin, m.refresh)
				next[f.Name] = now.Add(backoff[f.Name])
				continue
			}
			backoff[f.Name] = 0
			next[f.Name] = now.Add(m.refresh)
		}
	}
}

// retryAfter is the next backoff: first `first`, then doubling, capped at max.
func retryAfter(prev, first, max time.Duration) time.Duration {
	d := first
	if prev > 0 {
		d = prev * 2
	}
	if d > max {
		d = max
	}
	return d
}

func (m *Manager) stale(f Feed) bool {
	m.mu.Lock()
	st := m.status[f.Name]
	m.mu.Unlock()
	return st.Prefixes == 0 || time.Since(st.UpdatedAt) >= m.refresh
}

// Refresh fetches one feed and applies it if it passes every guard. It
// returns why it did not (nil on success).
func (m *Manager) Refresh(ctx context.Context, f Feed) error {
	now := time.Now()
	prefixes, err := m.fetch(ctx, f)
	if err != nil && ctx.Err() != nil {
		return ctx.Err() // shutting down: not a feed failure
	}
	if err == nil {
		m.mu.Lock()
		prev := m.active[f.Name]
		m.mu.Unlock()
		err = Check(f, prefixes, prev, m.limits)
	}
	m.mu.Lock()
	st := m.status[f.Name]
	st.LastAttempt = now
	if err != nil {
		st.LastError = err.Error()
		n := st.Prefixes
		m.mu.Unlock()
		log.Printf("[protectfeed] %s: refresh failed, keeping %d prefixes: %v", f.Name, n, err)
		return err
	}
	st.LastError = ""
	m.mu.Unlock()

	if err := writeCache(m.cachePath(f), f, prefixes); err != nil {
		log.Printf("[protectfeed] %s: cache write failed: %v", f.Name, err)
	}
	changed := m.accept(f, prefixes, now, false)
	if changed {
		log.Printf("[protectfeed] %s: %d prefixes active", f.Name, len(prefixes))
	}
	return nil
}

// accept makes p the active list; reports whether it differs from the last.
func (m *Manager) accept(f Feed, p []netip.Prefix, at time.Time, fromCache bool) bool {
	m.mu.Lock()
	changed := !equal(m.active[f.Name], p)
	m.active[f.Name] = p
	st := m.status[f.Name]
	st.Prefixes = len(p)
	st.IPv4, st.IPv6 = 0, 0
	for _, x := range p {
		if x.Addr().Is4() {
			st.IPv4++
		} else {
			st.IPv6++
		}
	}
	st.UpdatedAt = at
	st.FromCache = fromCache
	m.mu.Unlock()

	nets := make([]*net.IPNet, 0, len(p))
	for _, x := range p {
		nets = append(nets, &net.IPNet{IP: net.IP(x.Addr().AsSlice()), Mask: net.CIDRMask(x.Bits(), x.Addr().BitLen())})
	}
	if m.apply != nil {
		m.apply(f.Name, nets)
	}
	return changed
}

// Statuses returns a snapshot, in feed order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.feeds))
	for _, f := range m.feeds {
		out = append(out, *m.status[f.Name])
	}
	return out
}

func (m *Manager) cachePath(f Feed) string {
	return filepath.Join(m.cacheDir, f.Name+".txt")
}

func (m *Manager) fetch(ctx context.Context, f Feed) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "argus-protectfeed/1")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: HTTP %d", resp.StatusCode)
	}
	maxBody := m.limits.MaxBodyBytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("fetch: answer larger than %d bytes", maxBody)
	}
	return Parse(f.Format, body, m.limits)
}

// Parse decodes a feed answer. One unusable entry refuses the whole answer:
// a partial list is worse than the last good one.
func Parse(format string, body []byte, l Limits) ([]netip.Prefix, error) {
	l = l.withDefaults()
	var raw []string
	switch format {
	case FormatCloudflare:
		var doc struct {
			Success bool `json:"success"`
			Result  struct {
				IPv4 []string `json:"ipv4_cidrs"`
				IPv6 []string `json:"ipv6_cidrs"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("not a Cloudflare ips document: %w", err)
		}
		if !doc.Success {
			return nil, errors.New("Cloudflare answer is not a success document")
		}
		raw = append(doc.Result.IPv4, doc.Result.IPv6...)
	case FormatText:
		sc := bufio.NewScanner(strings.NewReader(string(body)))
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i != -1 {
				line = line[:i]
			}
			if line = strings.TrimSpace(line); line != "" {
				raw = append(raw, line)
			}
		}
	default:
		return nil, fmt.Errorf("unknown feed format %q", format)
	}
	out := make([]netip.Prefix, 0, len(raw))
	seen := map[netip.Prefix]bool{}
	for _, s := range raw {
		p, err := NormalizePrefix(s, l)
		if err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortPrefixes(out)
	return out, nil
}

// NormalizePrefix accepts a canonical, public, bounded CIDR.
func NormalizePrefix(s string, l Limits) (netip.Prefix, error) {
	l = l.withDefaults()
	p, err := netip.ParsePrefix(s)
	if err != nil || !strings.Contains(s, "/") {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: not a CIDR", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: host bits set", s)
	}
	a := p.Addr()
	if a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || overlapsSpecial(p) {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: not public unicast", s)
	}
	min := l.MinIPv4PrefixLen
	if a.Is6() {
		min = l.MinIPv6PrefixLen
	}
	if p.Bits() < min {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: broader than /%d", s, min)
	}
	return p, nil
}

var specialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64
}

// overlapsSpecial: the prefix touches a special range anywhere, not just at
// its first address (a /12 can hold a TEST-NET or benchmarking block).
func overlapsSpecial(p netip.Prefix) bool {
	for _, sp := range specialPrefixes {
		if sp.Overlaps(p) {
			return true
		}
	}
	return false
}

// Check applies the count window and the shrink/growth guards against the
// previously accepted list (none = nothing to compare).
func Check(f Feed, p, prev []netip.Prefix, l Limits) error {
	l = l.withDefaults()
	if f.MinPrefixes > 0 && len(p) < f.MinPrefixes {
		return fmt.Errorf("%d prefixes, want at least %d", len(p), f.MinPrefixes)
	}
	if f.MaxPrefixes > 0 && len(p) > f.MaxPrefixes {
		return fmt.Errorf("%d prefixes, want at most %d", len(p), f.MaxPrefixes)
	}
	if len(prev) == 0 {
		return nil
	}
	n4, n6 := countFamilies(p)
	o4, o6 := countFamilies(prev)
	for _, c := range []struct {
		fam    int
		n, old int
	}{{4, n4, o4}, {6, n6, o6}} {
		if c.old > 0 && float64(c.n) < float64(c.old)*l.MinShrink {
			return fmt.Errorf("IPv%d prefixes fell from %d to %d (partial answer?)", c.fam, c.old, c.n)
		}
	}
	s4, s6 := Space(p)
	e4, e6 := Space(prev)
	for _, c := range []struct {
		fam    int
		n, old uint64
		unit   string
	}{{4, s4, e4, "addresses"}, {6, s6, e6, "/64s"}} {
		if c.old == 0 {
			continue
		}
		if float64(c.n) > float64(c.old)*l.MaxSpaceGrowth {
			return fmt.Errorf("IPv%d space grew from %d to %d %s (poisoned answer?)", c.fam, c.old, c.n, c.unit)
		}
		if float64(c.n) < float64(c.old)*l.MinShrink {
			return fmt.Errorf("IPv%d space shrank from %d to %d %s (partial answer?)", c.fam, c.old, c.n, c.unit)
		}
	}
	return nil
}

func countFamilies(p []netip.Prefix) (v4, v6 int) {
	for _, x := range p {
		if x.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	return
}

// Space returns (IPv4 addresses, IPv6 /64s) covered, ignoring prefixes that
// sit inside another listed prefix. Prefix lengths are clamped by
// NormalizePrefix, so neither sum can overflow.
func Space(p []netip.Prefix) (v4, v6 uint64) {
	for i, x := range p {
		covered := false
		for j, y := range p {
			if i != j && y.Bits() < x.Bits() && y.Contains(x.Addr()) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if x.Addr().Is4() {
			v4 += 1 << (32 - x.Bits())
		} else if x.Bits() <= 64 {
			v6 += 1 << (64 - x.Bits())
		} else {
			v6++ // part of one /64
		}
	}
	return
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool {
		if c := p[i].Addr().Compare(p[j].Addr()); c != 0 {
			return c < 0
		}
		return p[i].Bits() < p[j].Bits()
	})
}

func equal(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readCache(path string, l Limits) ([]netip.Prefix, time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	p, err := Parse(FormatText, b, l)
	return p, fi.ModTime(), err
}

// writeCache replaces the cache file atomically.
func writeCache(path string, f Feed, p []netip.Prefix) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# argus protection feed %q from %s\n# fetched %s — generated, do not edit\n",
		f.Name, f.URL, time.Now().UTC().Format(time.RFC3339))
	for _, x := range p {
		sb.WriteString(x.String())
		sb.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+f.Name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
