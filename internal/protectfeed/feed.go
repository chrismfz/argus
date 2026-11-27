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

// Bounds on a single prefix (same as the cfm edge's trusted_proxies list).
const (
	MinIPv4PrefixLen = 12
	MinIPv6PrefixLen = 28
)

// Guard factors against the last accepted list.
const (
	maxSpaceGrowth = 2.0
	minShrink      = 0.5
	maxBodyBytes   = 1 << 20
)

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
	client   *http.Client
	apply    func(name string, nets []*net.IPNet)

	mu     sync.Mutex
	active map[string][]netip.Prefix
	status map[string]*Status
}

// New builds a manager. apply is called with every accepted list (from cache
// or fetch) and must replace that feed's previous list.
func New(feeds []Feed, cacheDir string, refresh time.Duration, apply func(name string, nets []*net.IPNet)) *Manager {
	if refresh <= 0 {
		refresh = 24 * time.Hour
	}
	m := &Manager{
		feeds:    feeds,
		cacheDir: cacheDir,
		refresh:  refresh,
		client:   &http.Client{Timeout: 30 * time.Second},
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
		p, mod, err := readCache(m.cachePath(f))
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
// refresh interval, then every interval, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	for _, f := range m.feeds {
		if m.stale(f) {
			m.Refresh(ctx, f)
		}
	}
	t := time.NewTicker(m.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, f := range m.feeds {
				m.Refresh(ctx, f)
			}
		}
	}
}

func (m *Manager) stale(f Feed) bool {
	m.mu.Lock()
	st := m.status[f.Name]
	m.mu.Unlock()
	return st.Prefixes == 0 || time.Since(st.UpdatedAt) >= m.refresh
}

// Refresh fetches one feed and applies it if it passes every guard.
func (m *Manager) Refresh(ctx context.Context, f Feed) {
	now := time.Now()
	prefixes, err := m.fetch(ctx, f)
	if err == nil {
		m.mu.Lock()
		prev := m.active[f.Name]
		m.mu.Unlock()
		err = Check(f, prefixes, prev)
	}
	m.mu.Lock()
	st := m.status[f.Name]
	st.LastAttempt = now
	if err != nil {
		st.LastError = err.Error()
		m.mu.Unlock()
		log.Printf("[protectfeed] %s: refresh refused, keeping %d prefixes: %v", f.Name, st.Prefixes, err)
		return
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("fetch: answer larger than %d bytes", maxBodyBytes)
	}
	return Parse(f.Format, body)
}

// Parse decodes a feed answer. One unusable entry refuses the whole answer:
// a partial list is worse than the last good one.
func Parse(format string, body []byte) ([]netip.Prefix, error) {
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
		p, err := NormalizePrefix(s)
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
func NormalizePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !strings.Contains(s, "/") {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: not a CIDR", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: host bits set", s)
	}
	a := p.Addr()
	if a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || isSpecial(a) {
		return netip.Prefix{}, fmt.Errorf("unusable entry %q: not public unicast", s)
	}
	min := MinIPv4PrefixLen
	if a.Is6() {
		min = MinIPv6PrefixLen
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

func isSpecial(a netip.Addr) bool {
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Check applies the count window and the shrink/growth guards against the
// previously accepted list (none = nothing to compare).
func Check(f Feed, p, prev []netip.Prefix) error {
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
		if c.old > 0 && float64(c.n) < float64(c.old)*minShrink {
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
		if float64(c.n) > float64(c.old)*maxSpaceGrowth {
			return fmt.Errorf("IPv%d space grew from %d to %d %s (poisoned answer?)", c.fam, c.old, c.n, c.unit)
		}
		if float64(c.n) < float64(c.old)*minShrink {
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
// sit inside another listed prefix. Prefix lengths are bounded by
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

func readCache(path string) ([]netip.Prefix, time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	p, err := Parse(FormatText, b)
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
