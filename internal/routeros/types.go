package routeros

import "time"

// ── Routes ────────────────────────────────────────────────────────────────────

// Route represents a single entry from /ip/route or /routing/route.
// RouterOS can have multiple routes for the same prefix with different distances —
// this is the multi-path visibility that eBGP alone cannot provide.
type Route struct {
	ID           string `json:"id"`
	DstAddress   string `json:"dst_address"`
	Gateway      string `json:"gateway"`      // next-hop IP
	Interface    string `json:"interface"`    // outgoing interface name (sfp1-Synapsecom etc.)
	RoutingTable string `json:"routing_table"`
	Distance     int    `json:"distance"`
	Scope        int    `json:"scope"`
	TargetScope  int    `json:"target_scope"`

	// Route status flags
	Active    bool `json:"active"`    // A flag — currently used
	Dynamic   bool `json:"dynamic"`   // D flag — learned dynamically
	IsBGP     bool `json:"is_bgp"`    // b flag
	Blackhole bool `json:"blackhole"` // blackhole route
	ECMP      bool `json:"ecmp"`      // equal-cost multipath

	// BGP-specific attributes (populated if IsBGP)
	BGPAttr *BGPRouteAttr `json:"bgp_attr,omitempty"`
}

// BGPRouteAttr holds BGP-specific attributes for a route as reported by RouterOS.
type BGPRouteAttr struct {
	LocalPref   int      `json:"local_pref"`
	MED         int      `json:"med"`
	Origin      string   `json:"origin"` // "igp", "egp", "incomplete"
	ASPath      []uint32 `json:"as_path"`
	Communities []string `json:"communities"`
	NextHop     string   `json:"next_hop"`
	OriginAS    uint32   `json:"origin_as"` // last ASN in path
}

// ── BGP Sessions ──────────────────────────────────────────────────────────────

// BGPSessionState mirrors RouterOS session states.
type BGPSessionState string

const (
	StateEstablished BGPSessionState = "established"
	StateActive      BGPSessionState = "active"
	StateConnect     BGPSessionState = "connect"
	StateIdle        BGPSessionState = "idle"
	StateOpenSent    BGPSessionState = "opensent"
	StateOpenConfirm BGPSessionState = "openconfirm"
	StateUnknown     BGPSessionState = "unknown"
)

// BGPSession represents a single BGP peer session from /routing/bgp/session.
type BGPSession struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	RemoteAddress string          `json:"remote_address"`
	RemoteAS      uint32          `json:"remote_as"`
	LocalAddress  string          `json:"local_address"`
	LocalAS       uint32          `json:"local_as"`
	State         BGPSessionState `json:"state"`
	Established   bool            `json:"established"`

	// Uptime is only meaningful when Established == true
	Uptime   time.Duration `json:"uptime_seconds"`
	UptimeRaw string       `json:"uptime_raw"` // raw RouterOS format e.g. "2d3h14m"

	// Prefix counts
	PrefixesReceived  int `json:"prefixes_received"`
	PrefixesAccepted  int `json:"prefixes_accepted"`
	PrefixesAdv       int `json:"prefixes_advertised"`

	// Flags
	Disabled bool `json:"disabled"`
	Dynamic  bool `json:"dynamic"`

	// The connection name in BGP peer config (useful for grouping)
	ConnectionName string `json:"connection_name,omitempty"`
}

// ── Filter Rules ──────────────────────────────────────────────────────────────

// FilterRule represents a single rule from /routing/filter/rule.
// Useful for understanding *why* a route has a certain local-pref or distance.
type FilterRule struct {
	ID       string `json:"id"`
	Chain    string `json:"chain"`    // e.g. "bgp-in-synapsecom"
	Rule     string `json:"rule"`     // raw rule text, e.g. "if (bgp-as-path 52055) { set bgp-local-pref 150; }"
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
}

// ── IP Addresses ──────────────────────────────────────────────────────────────

// IPAddress represents an entry from /ip/address — interface IP + subnet.
// Used by Pathfinder's upstream auto-discovery: next-hop IP falls in a subnet
// → we know which interface it belongs to → interface name = upstream label.
type IPAddress struct {
	ID        string `json:"id"`
	Address   string `json:"address"`   // e.g. "195.48.96.25/27" (includes prefix length)
	Network   string `json:"network"`   // e.g. "195.48.96.0" (just the network address)
	Interface string `json:"interface"` // e.g. "sfp2-GRIX"
	Disabled  bool   `json:"disabled"`
}

// ── NextHop ───────────────────────────────────────────────────────────────────

// NextHop represents an entry from /routing/nexthop.
type NextHop struct {
	ID        string `json:"id"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Resolved  bool   `json:"resolved"`
	Immediate string `json:"immediate_gw,omitempty"` // resolved next-hop if recursive
}
