package pathfinder

import "time"

// Path represents a single BGP path from GoBGP's RIB (best path only).
type Path struct {
	Prefix      string   `json:"prefix"`
	OriginAS    uint32   `json:"origin_as"`
	PeerASN     uint32   `json:"peer_asn,omitempty"`
	ASPath      []uint32 `json:"as_path"`
	NextHop     string   `json:"next_hop"`
	Upstream    string   `json:"upstream,omitempty"`
	LocalPref   uint32   `json:"local_pref"`
	Communities []string `json:"communities,omitempty"`
	IsBest      bool     `json:"is_best"`
}

// PrefixPaths holds the GoBGP best path and RouterOS all-paths for a prefix.
type PrefixPaths struct {
	Prefix   string         `json:"prefix"`
	BestPath *Path          `json:"best_path,omitempty"`
	AltPaths []Path         `json:"alt_paths,omitempty"`
	AllPaths []RouteSummary `json:"all_paths,omitempty"` // from RouterOS /routing/route
}

// ASNResult is the top-level response for an ASN-level query.
type ASNResult struct {
	ASN      uint32        `json:"asn"`
	Name     string        `json:"name,omitempty"`
	Prefixes []PrefixPaths `json:"prefixes"`
}

// RouteSummary is a per-path entry from RouterOS /routing/route detail.
// It carries the full picture: why a path was selected, its BGP attributes,
// and measured RTT from the router's perspective.
type RouteSummary struct {
	// Routing
	Gateway      string `json:"gateway"`      // next-hop IP
	Interface    string `json:"interface"`    // e.g. sfp1-Synapsecom
	Distance     int    `json:"distance"`     // 20 = Synapsecom, 30 = GR-IX
	Active       bool   `json:"active"`       // true = this path is forwarding
	Upstream     string `json:"upstream,omitempty"` // label derived from interface name
	LocalIP      string `json:"local_ip,omitempty"`  // our own IP on this peering link

	// Why this path was/wasn't chosen
	Contribution string `json:"contribution"` // "active","candidate","best-candidate"

	// BGP session info
	SessionName string `json:"session_name,omitempty"` // e.g. "AS8280-1", "rs1.thess.gr-ix.gr-IPv4-1"
	BelongsTo   string `json:"belongs_to,omitempty"`   // e.g. "bgp-IP-78.108.36.244"

	// BGP path attributes
	ASPath      []uint32 `json:"as_path,omitempty"`
	Hops        int      `json:"hops"`        // len(ASPath) — for quick comparison
	LocalPref   int      `json:"local_pref"`
	MED         int      `json:"med"`
	Communities []string `json:"communities,omitempty"`
	LargeCommunities []string `json:"large_communities,omitempty"`

	// RTT measured by router via /ping (0 if not measured)
	RTTms    float64 `json:"rtt_ms,omitempty"`
	RTTLoss  float64 `json:"rtt_loss_pct,omitempty"`
	RTTError string  `json:"rtt_error,omitempty"`
}

// ── Snapshot / diff — ROUTEWATCH foundation ───────────────────────────────────

// RIBSnapshot is a point-in-time copy of the best-path global RIB.
type RIBSnapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Paths     map[string]Path `json:"paths"` // keyed by prefix
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
