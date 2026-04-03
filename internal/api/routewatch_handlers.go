package api

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"argus/internal/bgpstate"
	"argus/internal/telemetry"
)

// ── Why GoBGP has only one path per prefix ────────────────────────────────────
//
// GoBGP (AS65001) peers with MikroTik only. MikroTik negotiates BGP capabilities
// mp,rr,gr,as4 with GoBGP — no "ap" (ADD-PATH). Without ADD-PATH, MikroTik sends
// only its elected best path per prefix to GoBGP. Multi-path data lives exclusively
// in RouterOS /routing/route, which Pathfinder queries on demand.
//
// Consequence: multi_path_count is always 0 here. Removed from response.
// Transit label is derived from the GoBGP AS-path — that IS accurate.
//
// Architecture:
//   /routewatch/status  → fast (0.3s), GoBGP + telemetry, transit-path overview
//   /pathfinder/prefix  → on-demand, RouterOS, actual multi-path detail

// ── result cache ──────────────────────────────────────────────────────────────
var (
	rwCacheMu      sync.RWMutex
	rwCachedResult map[string]interface{}
	rwCachedAt     time.Time
	rwCacheTTL     = 2 * time.Minute
)

// ── response types ────────────────────────────────────────────────────────────

type rwPrefixEntry struct {
	Prefix  string   `json:"prefix"`
	ASPath  []uint32 `json:"as_path,omitempty"`
	Hops    int      `json:"hops"`
	Transit string   `json:"transit,omitempty"` // first upstream label from AS-path
}

type rwASNEntry struct {
	ASN         uint32          `json:"asn"`
	Name        string          `json:"name,omitempty"`
	BytesIn1h   uint64          `json:"bytes_in_1h"`
	PrefixCount int             `json:"prefix_count"`
	Transits    []string        `json:"transits"`    // distinct transit labels seen
	Prefixes    []rwPrefixEntry `json:"prefixes,omitempty"` // top 10 by hops desc
}

// ── GET /routewatch/status ────────────────────────────────────────────────────
//
// Passive path intelligence: top 30 inbound ASNs joined with GoBGP GLOBAL RIB.
// Shows which transit each ASN is reached through and how many prefixes it has.
// Multi-path detail is NOT available here — use /pathfinder/prefix for that.
//
// Sources:
//   - telemetry ring → top 30 ASNs by bytes_in over last 60 min
//   - rib.Watcher    → GoBGP GLOBAL snapshot (best path per prefix)
//
// Cached for 2 minutes. One O(n) pass over the RIB. No router API calls.
func handleRouteWatchStatus(w http.ResponseWriter, r *http.Request) {
	if RIB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "RIB watcher not ready")
		return
	}

	rwCacheMu.RLock()
	cached, cacheAge := rwCachedResult, time.Since(rwCachedAt)
	rwCacheMu.RUnlock()
	if cached != nil && cacheAge < rwCacheTTL {
		w.Header().Set("X-Cache", "HIT")
		jsonOK(w, cached)
		return
	}
	w.Header().Set("X-Cache", "MISS")

	// 1. Top 30 inbound ASNs from last hour.
	var topIn []telemetry.ASNStat
	if telemetry.Global != nil {
		topIn, _ = telemetry.Global.QueryTopASN(30, 60)
	}
	wantASN := make(map[uint32]bool, len(topIn))
	for _, s := range topIn {
		wantASN[s.ASN] = true
	}

	// 2. One pass over the GoBGP GLOBAL RIB snapshot (best path per prefix).
	snap := RIB.Snapshot()

	type asnAccum struct {
		prefixes map[string]*rwPrefixEntry
		transits map[string]bool
	}
	byASN := make(map[uint32]*asnAccum, len(topIn))

	for prefix, entry := range snap {
		if entry.ActivePath == nil || len(entry.ActivePath.ASPath) == 0 {
			continue
		}
		originASN := entry.ActivePath.ASPath[len(entry.ActivePath.ASPath)-1]
		if !wantASN[originASN] {
			continue
		}

		transit := rwTransitLabel(entry.ActivePath.ASPath)

		acc, ok := byASN[originASN]
		if !ok {
			acc = &asnAccum{
				prefixes: make(map[string]*rwPrefixEntry),
				transits: make(map[string]bool),
			}
			byASN[originASN] = acc
		}
		acc.prefixes[prefix] = &rwPrefixEntry{
			Prefix:  prefix,
			ASPath:  entry.ActivePath.ASPath,
			Hops:    len(entry.ActivePath.ASPath),
			Transit: transit,
		}
		if transit != "" {
			acc.transits[transit] = true
		}
	}

	// 3. Assemble — preserve telemetry traffic ordering.
	totalPrefixes := 0
	entries := make([]rwASNEntry, 0, len(topIn))

	for _, stat := range topIn {
		e := rwASNEntry{
			ASN:       stat.ASN,
			Name:      stat.Name,
			BytesIn1h: stat.BytesIn,
			Transits:  []string{},
		}
		if acc, ok := byASN[stat.ASN]; ok {
			e.PrefixCount = len(acc.prefixes)
			totalPrefixes += e.PrefixCount

			// Top 10 prefixes by hop count descending (most complex paths first).
			all := make([]*rwPrefixEntry, 0, len(acc.prefixes))
			for _, pe := range acc.prefixes {
				all = append(all, pe)
			}
			sort.Slice(all, func(i, j int) bool {
				return all[i].Hops > all[j].Hops
			})
			if len(all) > 10 {
				all = all[:10]
			}
			for _, pe := range all {
				e.Prefixes = append(e.Prefixes, *pe)
			}
			for t := range acc.transits {
				e.Transits = append(e.Transits, t)
			}
			sort.Strings(e.Transits)
		}
		entries = append(entries, e)
	}

	result := map[string]interface{}{
		"asns":         entries,
		"asn_count":    len(entries),
		"prefix_count": totalPrefixes,
		"rib_size":     len(snap),
		"window_mins":  60,
		"computed_at":  time.Now().Unix(),
		"note":         "multi-path detail not available from GoBGP — use /pathfinder/prefix per prefix",
	}

	rwCacheMu.Lock()
	rwCachedResult = result
	rwCachedAt = time.Now()
	rwCacheMu.Unlock()

	jsonOK(w, result)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// rwTransitLabel derives a human-readable transit label from a GoBGP AS-path.
// The path starts with our ASN (e.g. 216285), then the first transit AS.
//
//	[216285, 8280, ...]  → "Synapsecom"   (via PathfinderResolver upstream map)
//	[216285, 6939, ...]  → "HE"
//	[216285, peerASN]    → "GR-IX"        (1 hop = direct IX peer)
//	[]                   → ""
func rwTransitLabel(asPath []uint32) string {
	if len(asPath) < 2 {
		return ""
	}
	// path[0] is our ASN, path[1] is the first transit (or direct peer)
	// If only 2 elements: [myASN, originASN] = direct IX peering
	if len(asPath) == 2 {
		return "GR-IX"
	}
	transitASN := asPath[1]

	// Use PathfinderResolver's upstream map if available — it reads from config.
	if PathfinderResolver != nil {
		if label := PathfinderResolver.TransitASNLabel(transitASN); label != "" {
			return label
		}
	}
	return fmt.Sprintf("AS%d", transitASN)
}

// bgpstate.PrefixEntry helpers used by the handler.
func rwOriginASN(e bgpstate.PrefixEntry) uint32 {
	if e.ActivePath == nil || len(e.ActivePath.ASPath) == 0 {
		return 0
	}
	return e.ActivePath.ASPath[len(e.ActivePath.ASPath)-1]
}
