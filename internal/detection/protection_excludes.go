package detection

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Concurrent-safe protection store
var (
	protectedIPs      = map[string]struct{}{}
	protectedPrefixes []*net.IPNet
	protectedLock     sync.RWMutex
	protectedLoadedAt time.Time

	// Ranges from protection feeds (internal/protectfeed), per feed name. Kept
	// apart from the exclusions above, which LoadProtectedFromDB replaces
	// wholesale on every reload.
	feedPrefixes = map[string][]*net.IPNet{}
)

// SetFeedProtected replaces the ranges of one protection feed.
func SetFeedProtected(name string, nets []*net.IPNet) {
	protectedLock.Lock()
	if len(nets) == 0 {
		delete(feedPrefixes, name)
	} else {
		feedPrefixes[name] = nets
	}
	protectedLock.Unlock()
}

// ProtectingFeed returns the name of the feed whose ranges cover ipStr, or "".
func ProtectingFeed(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	protectedLock.RLock()
	defer protectedLock.RUnlock()
	return feedFor(ip)
}

// feedFor needs protectedLock held.
func feedFor(ip net.IP) string {
	for name, nets := range feedPrefixes {
		for _, n := range nets {
			if n.Contains(ip) {
				return name
			}
		}
	}
	return ""
}

// LoadProtectedFromFile loads IPs/CIDRs (one per line) from a file.
// Lines starting with '#' or empty lines are ignored. Inline comments allowed.
func LoadProtectedFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("LoadProtectedFromFile: %w", err)
	}
	defer f.Close()

	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	sc := bufio.NewScanner(f)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip inline comment after whitespace or '#'
		if i := strings.Index(line, "#"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// keep first token only (allow "ip  # comment")
		if i := strings.IndexAny(line, " \t"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		if ip := net.ParseIP(line); ip != nil {
			ips[ip.String()] = struct{}{}
			continue
		}
		if _, nw, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, nw)
			continue
		}
		DlogEngine("LoadProtectedFromFile: skipping invalid entry %q (line %d)", line, lineno)
	}
	if err := sc.Err(); err != nil {
		return err
	}

	protectedLock.Lock()
	protectedIPs = ips
	protectedPrefixes = cidrs
	protectedLoadedAt = time.Now().UTC()
	protectedLock.Unlock()

	DlogEngine("LoadProtectedFromFile: loaded %d IPs and %d prefixes from %s", len(ips), len(cidrs), path)
	return nil
}

// IsProtected checks whether ipStr is in the protected exact list or CIDRs.
func IsProtected(ipStr string) bool {
	protectedLock.RLock()
	defer protectedLock.RUnlock()
	if ipStr == "" {
		return false
	}
	if _, ok := protectedIPs[ipStr]; ok {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range protectedPrefixes {
		if n.Contains(ip) {
			return true
		}
	}
	return feedFor(ip) != ""
}

// ShouldExecuteBlackhole returns false if blackhole should be skipped (log-only).
// reason is a short label for logging (e.g., "protected").
func ShouldExecuteBlackhole(ruleName, ip string) (ok bool, reason string) {
	if ip == "" {
		return false, "empty-target"
	}
	if IsProtected(ip) {
		if f := ProtectingFeed(ip); f != "" {
			return false, "protected (feed " + f + ")"
		}
		return false, "protected"
	}
	return true, ""
}

// Feed-covered addresses (CDN edges) keep matching scan rules all day; without
// a throttle their "skipped" audit rows would crowd real history out of the
// row-capped blackhole_events. Exclusions are rare and stay logged every time.
var (
	feedSkipMu       sync.Mutex
	feedSkipLast     = map[string]time.Time{}
	feedSkipInterval = 24 * time.Hour
)

// SetFeedSkipInterval sets how often a skipped blackhole of a feed-covered IP
// is recorded (<= 0 = every time).
func SetFeedSkipInterval(d time.Duration) {
	feedSkipMu.Lock()
	feedSkipInterval = d
	feedSkipMu.Unlock()
}

// recordFeedSkip reports whether this skip of a feed-covered ip should be
// logged now, and remembers it.
func recordFeedSkip(ip string, now time.Time) bool {
	feedSkipMu.Lock()
	defer feedSkipMu.Unlock()
	if feedSkipInterval <= 0 {
		return true
	}
	if last, ok := feedSkipLast[ip]; ok && now.Sub(last) < feedSkipInterval {
		return false
	}
	feedSkipLast[ip] = now
	if len(feedSkipLast) > 100000 { // bound: forget expired entries
		for k, t := range feedSkipLast {
			if now.Sub(t) >= feedSkipInterval {
				delete(feedSkipLast, k)
			}
		}
	}
	return true
}
