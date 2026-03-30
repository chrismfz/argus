package pathfinder

import (
	"context"
	"time"

	api "github.com/osrg/gobgp/v3/api"
)

// Snapshot takes a full point-in-time copy of the global best-path RIB.
// Only the best path per prefix is stored; all IPv4 unicast prefixes are captured.
// This is the basis for ROUTEWATCH's change-detection loop.
func (r *Resolver) Snapshot() (*RIBSnapshot, error) {
	snap := &RIBSnapshot{
		Timestamp: time.Now(),
		Paths:     make(map[string]Path),
	}

	err := r.server.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	}, func(d *api.Destination) {
		for _, p := range d.Paths {
			if p.Best {
				snap.Paths[d.Prefix] = r.parsePath(d.Prefix, p)
				break
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// DiffSnapshots compares two RIB snapshots and returns every path that changed.
//
// Change types emitted:
//   - ChangeWithdrawn     — prefix was in before, not in after
//   - ChangeNewPrefix     — prefix is in after, not in before
//   - ChangeNextHop       — next-hop IP changed (path switch)
//   - ChangeASPath        — AS-path changed (different route)
//   - ChangeUpstream      — upstream name changed (implies nexthop/community changed)
//   - ChangeLocalPref     — local-pref changed
//
// ROUTEWATCH Phase 1 watches ChangeWithdrawn on my_prefixes.
// ROUTEWATCH Phase 2 watches ChangeUpstream / ChangeASPath on high-traffic ASNs.
func DiffSnapshots(before, after *RIBSnapshot) []PathChange {
	var changes []PathChange

	// Withdrawn and modified prefixes
	for prefix, b := range before.Paths {
		a, exists := after.Paths[prefix]
		if !exists {
			bc := b
			changes = append(changes, PathChange{
				Prefix:     prefix,
				ChangeType: ChangeWithdrawn,
				Before:     &bc,
			})
			continue
		}
		// Check changes in priority order — report only the most significant
		if b.NextHop != a.NextHop {
			bc, ac := b, a
			changes = append(changes, PathChange{Prefix: prefix, ChangeType: ChangeNextHop, Before: &bc, After: &ac})
		} else if !asPathEqual(b.ASPath, a.ASPath) {
			bc, ac := b, a
			changes = append(changes, PathChange{Prefix: prefix, ChangeType: ChangeASPath, Before: &bc, After: &ac})
		} else if b.Upstream != a.Upstream {
			bc, ac := b, a
			changes = append(changes, PathChange{Prefix: prefix, ChangeType: ChangeUpstream, Before: &bc, After: &ac})
		} else if b.LocalPref != a.LocalPref {
			bc, ac := b, a
			changes = append(changes, PathChange{Prefix: prefix, ChangeType: ChangeLocalPref, Before: &bc, After: &ac})
		}
	}

	// New prefixes
	for prefix, a := range after.Paths {
		if _, exists := before.Paths[prefix]; !exists {
			ac := a
			changes = append(changes, PathChange{
				Prefix:     prefix,
				ChangeType: ChangeNewPrefix,
				After:      &ac,
			})
		}
	}

	return changes
}

func asPathEqual(a, b []uint32) bool {
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
