package api

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"argus/internal/bgpstate"
	"argus/internal/telemetry"
)

// ── result cache ──────────────────────────────────────────────────────────────
// /routewatch/status is expensive: it snapshots the entire adj-in RIB
// (potentially 2-3M path objects with add-path-out=all from Synapsecom/HE)
// and joins it with telemetry data.
//
// We cache the computed result for 2 minutes. The rib.Watcher itself refreshes
// every 5 minutes, so 2-minute cache staleness is well within the data refresh
// cadence. Page auto-refresh at 60s will hit the cache 2 times out of 3.
var (
	rwCacheMu      sync.RWMutex
	rwCachedResult map[string]interface{}
	rwCachedAt     time.Time
	rwCacheTTL     = 2 * time.Minute
)

// ── response types ────────────────────────────────────────────────────────────

type rwPathSummary struct {
	NextHop   string   `json:"next_hop"`
	Upstream  string   `json:"upstream,omitempty"`
	ASPath    []uint32 `json:"as_path,omitempty"`
	Hops      int      `json:"hops"`
	LocalPref uint32   `json:"local_pref,omitempty"`
	IsBest    bool     `json:"is_best"`
}

type rwPrefixEntry struct {
	Prefix    string          `json:"prefix"`
	PathCount int             `json:"path_count"`
	Paths     []rwPathSummary `json:"paths"`
}

type rwASNEntry struct {
	ASN            uint32          `json:"asn"`
	Name           string          `json:"name,omitempty"`
	BytesIn1h      uint64          `json:"bytes_in_1h"`
	PrefixCount    int             `json:"prefix_count"`
	MultiPathCount int             `json:"multi_path_count"`
	Upstreams      []string        `json:"upstreams"`
	Prefixes       []rwPrefixEntry `json:"prefixes,omitempty"` // top 5 by path diversity
}

// ── GET /routewatch/status ────────────────────────────────────────────────────
//
// Passive path intelligence: top 30 inbound ASNs joined with adj-in RIB data.
//
// Sources:
//   - telemetry ring  → top 30 ASNs by bytes_in over last 60 min
//   - rib.Watcher     → adj-in multi-path snapshot (all paths per prefix)
//
// One O(n) pass over the snapshot map. No router API calls. No probing.
func handleRouteWatchStatus(w http.ResponseWriter, r *http.Request) {
	if RIB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "RIB watcher not ready")
		return
	}

	// Serve from cache if fresh enough.
	rwCacheMu.RLock()
	cached, cacheAge := rwCachedResult, time.Since(rwCachedAt)
	rwCacheMu.RUnlock()

	if cached != nil && cacheAge < rwCacheTTL {
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("X-Cache-Age", cacheAge.Round(time.Second).String())
		jsonOK(w, cached)
		return
	}
	w.Header().Set("X-Cache", "MISS")

	// 1. Top 30 inbound ASNs from the last hour.
	var topIn []telemetry.ASNStat
	if telemetry.Global != nil {
		topIn, _ = telemetry.Global.QueryTopASN(30, 60)
	}

	wantASN := make(map[uint32]bool, len(topIn))
	trafficByASN := make(map[uint32]uint64, len(topIn))
	for _, s := range topIn {
		wantASN[s.ASN] = true
		trafficByASN[s.ASN] = s.BytesIn
	}

	// 2. One pass over the adj-in RIB snapshot.
	snap := RIB.Snapshot() // map[prefix]PrefixEntry, refreshed every 30s

	type asnAccum struct {
		prefixes map[string]*rwPrefixEntry
	}
	byASN := make(map[uint32]*asnAccum, len(topIn))

	for prefix, entry := range snap {
		originASN := rwOriginASN(entry)
		if originASN == 0 || !wantASN[originASN] {
			continue
		}
		acc, ok := byASN[originASN]
		if !ok {
			acc = &asnAccum{prefixes: make(map[string]*rwPrefixEntry)}
			byASN[originASN] = acc
		}
		paths := rwBuildPaths(entry)
		acc.prefixes[prefix] = &rwPrefixEntry{
			Prefix:    prefix,
			PathCount: len(paths),
			Paths:     paths,
		}
	}

	// 3. Assemble — preserve telemetry traffic ordering.
	totalPrefixes, totalMultiPath := 0, 0
	entries := make([]rwASNEntry, 0, len(topIn))

	for _, stat := range topIn {
		e := rwASNEntry{
			ASN:       stat.ASN,
			Name:      stat.Name,
			BytesIn1h: stat.BytesIn,
			Upstreams: []string{},
		}
		if acc, ok := byASN[stat.ASN]; ok {
			e.PrefixCount = len(acc.prefixes)
			totalPrefixes += e.PrefixCount

			upSet := make(map[string]bool)
			all := make([]*rwPrefixEntry, 0, len(acc.prefixes))
			for _, pe := range acc.prefixes {
				if pe.PathCount > 1 {
					e.MultiPathCount++
					totalMultiPath++
				}
				for _, p := range pe.Paths {
					if p.Upstream != "" {
						upSet[p.Upstream] = true
					}
				}
				all = append(all, pe)
			}
			// Top 5 prefixes with most path diversity for the expand view.
			sort.Slice(all, func(i, j int) bool {
				return all[i].PathCount > all[j].PathCount
			})
			if len(all) > 5 {
				all = all[:5]
			}
			for _, pe := range all {
				e.Prefixes = append(e.Prefixes, *pe)
			}
			for u := range upSet {
				e.Upstreams = append(e.Upstreams, u)
			}
			sort.Strings(e.Upstreams)
		}
		entries = append(entries, e)
	}

	result := map[string]interface{}{
		"asns":             entries,
		"asn_count":        len(entries),
		"prefix_count":     totalPrefixes,
		"multi_path_count": totalMultiPath,
		"rib_size":         len(snap),
		"window_mins":      60,
		"computed_at":      time.Now().Unix(),
	}

	// Store in cache.
	rwCacheMu.Lock()
	rwCachedResult = result
	rwCachedAt = time.Now()
	rwCacheMu.Unlock()

	jsonOK(w, result)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func rwOriginASN(e bgpstate.PrefixEntry) uint32 {
	if e.ActivePath == nil || len(e.ActivePath.ASPath) == 0 {
		return 0
	}
	return e.ActivePath.ASPath[len(e.ActivePath.ASPath)-1]
}

func rwBuildPaths(e bgpstate.PrefixEntry) []rwPathSummary {
	var out []rwPathSummary
	if e.ActivePath != nil {
		out = append(out, rwToSummary(*e.ActivePath, true))
	}
	for _, alt := range e.AltPaths {
		out = append(out, rwToSummary(alt, false))
	}
	return out
}

func rwToSummary(p bgpstate.PathInfo, best bool) rwPathSummary {
	return rwPathSummary{
		NextHop:   p.NextHop,
		Upstream:  p.Upstream,
		ASPath:    p.ASPath,
		Hops:      len(p.ASPath),
		LocalPref: p.LocalPref,
		IsBest:    best,
	}
}
