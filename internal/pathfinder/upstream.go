package pathfinder

import "strings"

// UpstreamMap resolves a human-readable upstream name from BGP path attributes.
//
// Resolution priority (first match wins):
//  1. BGP community value  → community_map in config
//  2. First-hop transit AS → transit_asn_map in config  (works without community tagging)
//  3. Next-hop IP          → nexthop_map in config       (fallback)
//
// Without community tagging on MikroTik, the transit ASN approach is the most
// practical: Synapsecom (AS8280) will appear as ASPath[1] for transit routes,
// while direct GR-IX peers arrive with their own ASN first.
type UpstreamMap struct {
	// "asn:value" → upstream name, e.g. "216285:8280" → "Synapsecom"
	CommunityMap map[string]string
	// transit ASN (uint32) → upstream name, e.g. 8280 → "Synapsecom"
	TransitASNMap map[uint32]string
	// next-hop IP string → upstream name
	NextHopMap map[string]string
	// MyASN is stripped from the head of AS-paths before transit-ASN lookup
	MyASN uint32
}

// NewUpstreamMap creates an UpstreamMap from the config values.
func NewUpstreamMap(communityMap map[string]string, transitASNMap map[uint32]string, nextHopMap map[string]string, myASN uint32) *UpstreamMap {
	return &UpstreamMap{
		CommunityMap:  communityMap,
		TransitASNMap: transitASNMap,
		NextHopMap:    nextHopMap,
		MyASN:         myASN,
	}
}

// Resolve returns the upstream name for a path's attributes, or "" if unknown.
func (u *UpstreamMap) Resolve(communities []string, asPath []uint32, nextHop string) string {
	if u == nil {
		return ""
	}

	// 1. Community map
	for _, c := range communities {
		if name, ok := u.CommunityMap[strings.TrimSpace(c)]; ok {
			return name
		}
	}

	// 2. Transit ASN — strip our own ASN from the head first
	path := asPath
	if len(path) > 0 && path[0] == u.MyASN {
		path = path[1:]
	}
	if len(path) > 0 {
		if name, ok := u.TransitASNMap[path[0]]; ok {
			return name
		}
	}

	// 3. Next-hop IP
	if name, ok := u.NextHopMap[nextHop]; ok {
		return name
	}

	return ""
}
