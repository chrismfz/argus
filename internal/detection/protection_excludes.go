package detection

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// Feed-covered addresses (CDN edges) keep matching scan rules all day. The
// audit log's own per-IP cooldown (allowSkipEvent, 60s) still lets each edge
// write up to 1440 "skipped" rows a day, which would crowd real history out of
// the row-capped blackhole_events; this throttle makes it one per interval.
// Exclusions keep only the 60s cooldown.
var (
	feedSkipMu       sync.Mutex
	feedSkipLast     = map[string]time.Time{}
	feedSkipInterval = 24 * time.Hour
	feedSkipPruned   time.Time

	feedSuppressAlerts atomic.Bool
)

// SetFeedSuppressAlerts makes feed-covered IPs skip a rule's alert action as
// well as its blackhole (protection_feeds.suppress_alerts).
func SetFeedSuppressAlerts(on bool) { feedSuppressAlerts.Store(on) }

// alertSuppressedByFeed reports whether an alert for ip is dropped because a
// protection feed covers it.
func alertSuppressedByFeed(ip string) bool {
	return feedSuppressAlerts.Load() && ProtectingFeed(ip) != ""
}

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
	// Forget expired entries once per interval, so the map holds at most one
	// interval's worth of IPs.
	if now.Sub(feedSkipPruned) >= feedSkipInterval {
		for k, t := range feedSkipLast {
			if now.Sub(t) >= feedSkipInterval {
				delete(feedSkipLast, k)
			}
		}
		feedSkipPruned = now
	}
	return true
}
