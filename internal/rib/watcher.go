// Package rib maintains a live multi-path BGP RIB by periodically polling
// GoBGP's adj-in table (all paths per prefix, not just best).
//
// # Phase 1 — stub (current)
//
// Run() is a no-op placeholder. The RIB map starts empty and is never
// populated. The bgpstate.RIBReader interface is fully implemented, so every
// consumer (BGP cockpit handlers, routewatch) can be wired against this
// package today without any conditional compilation or nil-guards in callers.
//
// # Phase 2 — ROUTEWATCH
//
// When routewatch begins, Run() gains a periodic ListPath loop using
// TableType_ADJ_IN (per the ROUTEWATCH design doc). Every poll replaces the
// PrefixEntry map atomically. routewatch then calls GetPrefix / Snapshot to
// drive its probe and diff loops.
//
// The upgrade is entirely contained inside this package. No callers change.
package rib

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgppkt "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"

	"argus/internal/bgpstate"
)

// Watcher subscribes to GoBGP and maintains a live multi-path RIB.
// It implements bgpstate.RIBReader.
//
// Safe for concurrent use — all map access is guarded by mu.
type Watcher struct {
	server   *gobgpserver.BgpServer
	upstream bgpstate.UpstreamLabeler // may be nil
	geo      bgpstate.GeoLookup      // may be nil
	interval time.Duration           // poll interval for Phase 2 adj-in refresh

	mu      sync.RWMutex
	entries map[string]*bgpstate.PrefixEntry // keyed by prefix CIDR string
}

// New creates a Watcher. Both upstream and geo are optional — pass nil to
// disable upstream labeling / ASN name enrichment respectively.
//
// main.go wiring (add after Pathfinder is initialised):
//
//	ribWatcher := rib.New(listener.Server, upstreamMap, geo)
//	go ribWatcher.Run(ctx)
//	api.RIB = ribWatcher           // api expects bgpstate.RIBReader
//	// routewatch.New(..., ribWatcher, ...) — Phase 2
func New(server *gobgpserver.BgpServer, upstream bgpstate.UpstreamLabeler, geo bgpstate.GeoLookup) *Watcher {
	return &Watcher{
		server:   server,
		upstream: upstream,
		geo:      geo,
		interval: 30 * time.Second,
		entries:  make(map[string]*bgpstate.PrefixEntry),
	}
}

// Run starts the RIB refresh loop and blocks until ctx is cancelled.
//
// Phase 1 (stub): logs startup and parks on ctx.Done().
//
// Phase 2 (ROUTEWATCH): replace the stub body with the refresh loop below.
func (w *Watcher) Run(ctx context.Context) {
	log.Println("[rib] watcher started (Phase 1 stub — adj-in polling pending ROUTEWATCH)")

	// ── ROUTEWATCH Phase 2 — replace stub body with: ─────────────────────────
	//
	//   if err := w.refresh(ctx); err != nil {
	//       log.Printf("[rib] initial adj-in load failed: %v", err)
	//   }
	//   ticker := time.NewTicker(w.interval)
	//   defer ticker.Stop()
	//   for {
	//       select {
	//       case <-ticker.C:
	//           if err := w.refresh(ctx); err != nil {
	//               log.Printf("[rib] adj-in refresh failed: %v", err)
	//           }
	//       case <-ctx.Done():
	//           log.Println("[rib] watcher stopped")
	//           return
	//       }
	//   }
	//
	// ─────────────────────────────────────────────────────────────────────────

	<-ctx.Done()
	log.Println("[rib] watcher stopped")
}

// ── bgpstate.RIBReader implementation ────────────────────────────────────────

// GetPrefix returns the current PrefixEntry for a given CIDR string.
// Returns (nil, false) if the prefix is not in the RIB.
func (w *Watcher) GetPrefix(prefix string) (*bgpstate.PrefixEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	e, ok := w.entries[prefix]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

// GetPrefixesForASN returns all PrefixEntries whose active path originates from
// or passes through the given ASN. Used by the BGP cockpit and ROUTEWATCH.
func (w *Watcher) GetPrefixesForASN(asn uint32) []bgpstate.PrefixEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []bgpstate.PrefixEntry
	for _, e := range w.entries {
		if entryMatchesASN(e, asn) {
			out = append(out, *e)
		}
	}
	return out
}

// Snapshot returns a point-in-time deep copy of the entire multi-path RIB,
// keyed by prefix CIDR string. Used by ROUTEWATCH for periodic diff-based
// change detection (complements pathfinder.RIBSnapshot with alt-path data).
func (w *Watcher) Snapshot() map[string]bgpstate.PrefixEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[string]bgpstate.PrefixEntry, len(w.entries))
	for k, e := range w.entries {
		out[k] = *e
	}
	return out
}

// ── Phase 2 internals (uncommented in Run once ROUTEWATCH begins) ─────────────

// refresh polls GoBGP's adj-in table for all IPv4 unicast paths across all
// peers, then atomically replaces the entries map.
//
// ListPath with TableType_ADJ_IN returns api.Destination values where
// .Prefix is already a human-readable CIDR string — no NLRI unmarshaling
// needed. This is the pattern recommended by the ROUTEWATCH design doc and
// mirrors how pathfinder/resolver.go queries the GLOBAL table today.
func (w *Watcher) refresh(ctx context.Context) error {
	next := make(map[string]*bgpstate.PrefixEntry)

	err := w.server.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_ADJ_IN,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	}, func(d *api.Destination) {
		e := &bgpstate.PrefixEntry{
			Prefix:     d.Prefix,
			LastUpdate: time.Now(),
		}
		for _, p := range d.Paths {
			info := w.parsePath(p)
			if p.Best {
				cp := info
				e.ActivePath = &cp
			} else {
				e.AltPaths = append(e.AltPaths, info)
			}
		}
		next[d.Prefix] = e
	})
	if err != nil {
		return fmt.Errorf("ListPath adj-in: %w", err)
	}

	w.mu.Lock()
	w.entries = next
	w.mu.Unlock()

	log.Printf("[rib] adj-in refresh: %d prefixes, %d with alt paths",
		len(next), countMultipath(next))
	return nil
}

// ── Path parsing ─────────────────────────────────────────────────────────────

// parsePath decodes a raw GoBGP api.Path into a bgpstate.PathInfo.
//
// Mirrors the attribute parsing in pathfinder/resolver.go but produces
// bgpstate.PathInfo rather than pathfinder.Path, and captures the full
// attribute set needed by ROUTEWATCH (MED, large communities, origin).
func (w *Watcher) parsePath(p *api.Path) bgpstate.PathInfo {
	out := bgpstate.PathInfo{
		IsBest:      p.Best,
		LearnedFrom: p.NeighborIp, // peer IP; ROUTEWATCH maps to session name
		LearnedAt:   time.Now(),
	}

	attrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
	if err != nil {
		return out
	}

	for _, attr := range attrs {
		switch v := attr.(type) {

		case *bgppkt.PathAttributeNextHop:
			out.NextHop = v.Value.String()

		case *bgppkt.PathAttributeMpReachNLRI:
			if v.Nexthop != nil {
				out.NextHop = v.Nexthop.String()
			}

		case *bgppkt.PathAttributeAsPath:
			for _, seg := range v.Value {
				switch s := seg.(type) {
				case *bgppkt.AsPathParam:
					for _, asn := range s.AS {
						out.ASPath = append(out.ASPath, uint32(asn))
					}
				case *bgppkt.As4PathParam:
					out.ASPath = append(out.ASPath, s.AS...)
				}
			}

		case *bgppkt.PathAttributeLocalPref:
			out.LocalPref = v.Value

		case *bgppkt.PathAttributeMultiExitDisc:
			out.MED = int(v.Value)

		case *bgppkt.PathAttributeCommunities:
			for _, c := range v.Value {
				out.Communities = append(out.Communities, communityString(c))
			}

		case *bgppkt.PathAttributeLargeCommunities:
			for _, lc := range v.Values {
				out.LargeCommunities = append(out.LargeCommunities, largeCommunityString(lc))
			}

		case *bgppkt.PathAttributeOrigin:
			switch v.Value {
			case bgppkt.BGP_ORIGIN_ATTR_TYPE_IGP:
				out.Origin = "igp"
			case bgppkt.BGP_ORIGIN_ATTR_TYPE_EGP:
				out.Origin = "egp"
			default:
				out.Origin = "incomplete"
			}
		}
	}

	// Resolve upstream label: community → transit ASN → next-hop IP
	if w.upstream != nil {
		out.Upstream = w.upstream.Resolve(out.Communities, out.ASPath, out.NextHop)
	}

	return out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func communityString(c uint32) string {
	return fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)
}

func largeCommunityString(lc *bgppkt.LargeCommunity) string {
	return fmt.Sprintf("%d:%d:%d", lc.GlobalAdministrator, lc.LocalData1, lc.LocalData2)
}

func entryMatchesASN(e *bgpstate.PrefixEntry, asn uint32) bool {
	if e.ActivePath == nil {
		return false
	}
	for _, a := range e.ActivePath.ASPath {
		if a == asn {
			return true
		}
	}
	return false
}

func countMultipath(entries map[string]*bgpstate.PrefixEntry) int {
	n := 0
	for _, e := range entries {
		if len(e.AltPaths) > 0 {
			n++
		}
	}
	return n
}
