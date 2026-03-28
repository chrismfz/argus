
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
)

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
	return false
}

// ShouldExecuteBlackhole returns false if blackhole should be skipped (log-only).
// reason is a short label for logging (e.g., "protected").
func ShouldExecuteBlackhole(ruleName, ip string) (ok bool, reason string) {
	if ip == "" {
		return false, "empty-target"
}
	if IsProtected(ip) {
		return false, "protected"
	}
	return true, ""
}
