package pathfinder

import "time"

// Path represents a single BGP path for a prefix.
type Path struct {
	Prefix      string   `json:"prefix"`
	OriginAS    uint32   `json:"origin_as"`
	ASPath      []uint32 `json:"as_path"`
	NextHop     string   `json:"next_hop"`
	Upstream    string   `json:"upstream,omitempty"` // derived from communities / next-hop / transit ASN
	LocalPref   uint32   `json:"local_pref"`
	Communities []string `json:"communities,omitempty"`
	IsBest      bool     `json:"is_best"`
}

// PrefixPaths holds the best path and any alternative paths for a prefix.
type PrefixPaths struct {
	Prefix   string `json:"prefix"`
	BestPath *Path  `json:"best_path,omitempty"`
	AltPaths []Path `json:"alt_paths,omitempty"`
}

// ASNResult is the top-level response for an ASN-level query.
type ASNResult struct {
	ASN      uint32        `json:"asn"`
	Name     string        `json:"name,omitempty"`
	Prefixes []PrefixPaths `json:"prefixes"`
}

// ── Snapshot / diff types — ROUTEWATCH foundation ─────────────────────────────

// RIBSnapshot is a point-in-time copy of the best-path global RIB.
type RIBSnapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Paths     map[string]Path `json:"paths"` // keyed by prefix string
}

// ChangeKind describes what changed between two snapshots.
type ChangeKind string

const (
	ChangeWithdrawn ChangeKind = "withdrawn"
	ChangeNewPrefix ChangeKind = "new_prefix"
	ChangeNextHop   ChangeKind = "nexthop_changed"
	ChangeASPath    ChangeKind = "aspath_changed"
	ChangeUpstream  ChangeKind = "upstream_changed"
	ChangeLocalPref ChangeKind = "localpref_changed"
)

// PathChange describes a single change between two RIB snapshots.
type PathChange struct {
	Prefix     string     `json:"prefix"`
	ChangeType ChangeKind `json:"change_type"`
	Before     *Path      `json:"before,omitempty"`
	After      *Path      `json:"after,omitempty"`
}
