package api

// hardened.go — defence-in-depth middleware for the argus API server.
//
// Layer order (outermost → innermost):
//   withRecovery → globalGuard → [mux routing] → WithAuth / WithMainIPOnly
//
// globalGuard responsibilities:
//   1. Loopback: always trusted (nginx, local tools) — no checks.
//   2. Allowlisted IPs: rate-limited at 200 req/min, otherwise trusted.
//   3. Unknown IPs: must carry a valid Bearer token; failing that → 403 +
//      failure counter. After banThreshold failures within the window the IP
//      is silently temp-banned for banDuration.
//   4. Request body capped at 64 KiB — stops body-flooding.
//
// Route-level WithAuth / WithMainIPOnly still run as a second gate.
// This is intentional: defence in depth — the global guard blocks strangers
// before routing even begins.

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"argus/internal/config"
)

// ── Tuning ────────────────────────────────────────────────────────────────────

const (
	// Rate limiting — single tier, applies to all non-loopback callers
	rlWindow     = 60 * time.Second
	rlMax        = 200 // requests/window

	// Abuse / ban
	banWindow    = 60 * time.Second
	banThreshold = 10 // auth failures within banWindow → ban
	banDuration  = 15 * time.Minute

	// Housekeeping
	cleanupEvery = 5 * time.Minute

	// Body cap
	maxBodyBytes = 64 << 10 // 64 KiB
)

// ── Per-IP state ──────────────────────────────────────────────────────────────

type ipEntry struct {
	requests    []time.Time // timestamps of recent requests (rate limiting)
	failures    []time.Time // timestamps of recent auth failures
	bannedUntil time.Time
}

var (
	ipTable   = make(map[string]*ipEntry)
	ipTableMu sync.Mutex
)

func init() {
	go func() {
		t := time.NewTicker(cleanupEvery)
		for range t.C {
			pruneIPTable()
		}
	}()
}

func pruneIPTable() {
	ipTableMu.Lock()
	defer ipTableMu.Unlock()
	now := time.Now()
	for addr, e := range ipTable {
		e.requests = recentOnly(e.requests, rlWindow, now)
		e.failures = recentOnly(e.failures, banWindow, now)
		if len(e.requests) == 0 && len(e.failures) == 0 && now.After(e.bannedUntil) {
			delete(ipTable, addr)
		}
	}
}

func recentOnly(ts []time.Time, window time.Duration, now time.Time) []time.Time {
	cutoff := now.Add(-window)
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func entry(addr string) *ipEntry {
	if e, ok := ipTable[addr]; ok {
		return e
	}
	e := &ipEntry{}
	ipTable[addr] = e
	return e
}

// ── Public helpers (called from globalGuard) ──────────────────────────────────

// checkBanned returns true if this IP is currently temp-banned.
func checkBanned(addr string) bool {
	ipTableMu.Lock()
	defer ipTableMu.Unlock()
	e, ok := ipTable[addr]
	if !ok {
		return false
	}
	return time.Now().Before(e.bannedUntil)
}

// checkRate returns true (allow) or false (rate-limit exceeded).
// max is the per-window ceiling for this caller class.
func checkRate(addr string, max int) bool {
	ipTableMu.Lock()
	defer ipTableMu.Unlock()
	now := time.Now()
	e := entry(addr)
	e.requests = recentOnly(e.requests, rlWindow, now)
	if len(e.requests) >= max {
		return false
	}
	e.requests = append(e.requests, now)
	return true
}

// recordFailure bumps the auth-failure counter for addr.
// Returns true if the IP just crossed the ban threshold.
func recordFailure(addr string) bool {
	ipTableMu.Lock()
	defer ipTableMu.Unlock()
	now := time.Now()
	e := entry(addr)
	e.failures = recentOnly(e.failures, banWindow, now)
	e.failures = append(e.failures, now)
	if len(e.failures) >= banThreshold {
		e.bannedUntil = now.Add(banDuration)
		return true
	}
	return false
}

// ── tokenValid checks the Bearer header against configured tokens ─────────────

func tokenValid(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if len(auth) <= 7 || auth[:7] != "Bearer " {
		return false
	}
	tok := auth[7:]
	for _, t := range config.AppConfig.API.Tokens {
		if tok == t {
			return true
		}
	}
	return false
}

// ── globalGuard ───────────────────────────────────────────────────────────────
//
// Access model:
//   - Loopback (127.x / ::1): always trusted — nginx proxy, local tools.
//   - allow_ips: trusted, rate-limited at 200 req/min.
//   - Everyone else: 403. Period.
//     Exception: a valid Bearer token grants entry at the same rate limit.
//     This exists only for backward compatibility (e.g. CFM calling before its
//     IP is added to allow_ips). It is not a second-class citizen — token
//     callers get the same rate limit as allowlisted IPs.
//     Long-term: add all callers to allow_ips and remove token reliance.
//
// Every rejected unknown-IP request (token or not) counts toward a failure
// counter. 10 failures in 60 s → 15 min temp-ban.

func globalGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)

		if ip == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// ── Loopback: unconditionally trusted ─────────────────────────────────
		if ip.IsLoopback() {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			next.ServeHTTP(w, r)
			return
		}

		// ── Temp-ban check (cheap, runs before anything else) ─────────────────
		if checkBanned(host) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// ── IP allowlist — primary gate ───────────────────────────────────────
		if !ipAllowed(r, config.AppConfig.API.AllowIPs) {
			// Token fallback: backward-compat only (e.g. CFM before IP is listed)
			if !tokenValid(r) {
				banned := recordFailure(host)
				if banned {
					log.Printf("[GUARD] temp-banned %s after %d auth failures", host, banThreshold)
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			// Valid token from unknown IP — log it so you know to add the IP
			log.Printf("[GUARD] token-auth from unlisted IP %s — consider adding to allow_ips", host)
		}

		// ── Rate limit — single tier for all non-loopback callers ─────────────
		if !checkRate(host, rlMax) {
			log.Printf("[GUARD] rate-limited %s", host)
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// ── withRecovery ──────────────────────────────────────────────────────────────
// Catches panics in any handler so they can't crash the server.

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rc := recover(); rc != nil {
				log.Printf("[API] panic recovered in %s: %v", r.URL.Path, rc)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ── notFoundHandler ───────────────────────────────────────────────────────────
// Returns 403 (not 404) for unregistered paths.
// Scanners probing /wp-admin, /.env, /cgi-bin, etc. get nothing useful back,
// and every hit counts toward their failure / ban quota.

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() && !ipAllowed(r, config.AppConfig.API.AllowIPs) {
		banned := recordFailure(host)
		if banned {
			log.Printf("[GUARD] temp-banned %s (scanner probe: %s)", host, r.URL.Path)
		}
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
}
