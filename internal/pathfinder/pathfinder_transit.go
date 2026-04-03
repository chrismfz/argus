package pathfinder

import "fmt"

// TransitASNLabel returns the human-readable name for a transit ASN,
// using the TransitASNMap from config (e.g. 8280 → "Synapsecom").
// Returns "" if upstream is nil or the ASN is not in the map.
//
// Used by the ROUTEWATCH handler to label transits from GoBGP AS-paths
// without importing the full UpstreamMap type into the api package.
func (r *Resolver) TransitASNLabel(asn uint32) string {
	if r.upstream == nil {
		return ""
	}
	if name, ok := r.upstream.TransitASNMap[asn]; ok {
		return name
	}
	return fmt.Sprintf("AS%d", asn)
}
