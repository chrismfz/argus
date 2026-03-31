package routeros

import "time"

// ── Routes ────────────────────────────────────────────────────────────────────

// Route represents a single entry from /routing/route (full RIB, all candidates).
type Route struct {
	ID           string `json:"id"`
	DstAddress   string `json:"dst_address"`
	Gateway      string `json:"gateway"`      // next-hop IP
	Interface    string `json:"interface"`    // outgoing interface (sfp1-Synapsecom)
	RoutingTable string `json:"routing_table"`
	Distance     int    `json:"distance"`
	Scope        int    `json:"scope"`
	TargetScope  int    `json:"target_scope"`

	// Route status
	Active    bool `json:"active"`    // contribution == "active"
	Dynamic   bool `json:"dynamic"`
	IsBGP     bool `json:"is_bgp"`
	Blackhole bool `json:"blackhole"`
	ECMP      bool `json:"ecmp"`

	// Full BGP attributes (from /routing/route detail)
	BGPAttr *BGPRouteAttr `json:"bgp_attr,omitempty"`
}

// BGPRouteAttr holds BGP-specific attributes as reported by RouterOS.
// Fields from /routing/route print detail (RouterOS 7).
type BGPRouteAttr struct {
	LocalPref   int      `json:"local_pref"`
	MED         int      `json:"med"`
	Origin      string   `json:"origin"` // "igp", "egp", "incomplete"
	ASPath      []uint32 `json:"as_path"`
	Communities []string `json:"communities,omitempty"`
	LargeCommunities []string `json:"large_communities,omitempty"`
	NextHop     string   `json:"next_hop"`
	OriginAS    uint32   `json:"origin_as"` // last ASN in path

	// RouterOS 7 /routing/route detail specific fields
	SessionName  string `json:"session_name"`  // e.g. "AS8280-1", "rs1.thess.gr-ix.gr-IPv4-1"
	BelongsTo    string `json:"belongs_to"`    // e.g. "bgp-IP-78.108.36.244"
	Contribution string `json:"contribution"`  // "active", "candidate", "best-candidate"
}

// ── BGP Peers ─────────────────────────────────────────────────────────────────

// BGPPeer is a configured BGP connection from /rest/routing/bgp/connection.
type BGPPeer struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RemoteAddress string `json:"remote_address"`
	RemoteAS      uint32 `json:"remote_as"`
	LocalAddress  string `json:"local_address"`
	LocalAS       uint32 `json:"local_as"`
	Disabled      bool   `json:"disabled"`
	Comment       string `json:"comment"`
}

// ── BGP Sessions ──────────────────────────────────────────────────────────────

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

type BGPSession struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	RemoteAddress string          `json:"remote_address"`
	RemoteAS      uint32          `json:"remote_as"`
	LocalAddress  string          `json:"local_address"`
	LocalAS       uint32          `json:"local_as"`
	State         BGPSessionState `json:"state"`
	Established   bool            `json:"established"`
	Uptime        time.Duration   `json:"uptime_seconds"`
	UptimeRaw     string          `json:"uptime_raw"`
	PrefixesReceived int          `json:"prefixes_received"`
	PrefixesAdv      int          `json:"prefixes_advertised"`
	Disabled      bool            `json:"disabled"`
	Dynamic       bool            `json:"dynamic"`
	ConnectionName string         `json:"connection_name,omitempty"`
}

// ── Filter Rules ──────────────────────────────────────────────────────────────

type FilterRule struct {
	ID       string `json:"id"`
	Chain    string `json:"chain"`
	Rule     string `json:"rule"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
}

// ── IP Addresses ──────────────────────────────────────────────────────────────

type IPAddress struct {
	ID        string `json:"id"`
	Address   string `json:"address"` // includes prefix len: "195.48.96.25/27"
	Network   string `json:"network"` // "195.48.96.0"
	Interface string `json:"interface"`
	Disabled  bool   `json:"disabled"`
}

// ── NextHop ───────────────────────────────────────────────────────────────────

type NextHop struct {
	ID        string `json:"id"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Resolved  bool   `json:"resolved"`
	Immediate string `json:"immediate_gw,omitempty"`
}

// ── Ping ──────────────────────────────────────────────────────────────────────

// PingResult holds the result of a /ping call to RouterOS.
type PingResult struct {
	Host     string  `json:"host"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	AvgRTTms float64 `json:"avg_rtt_ms"`
	MinRTTms float64 `json:"min_rtt_ms"`
	MaxRTTms float64 `json:"max_rtt_ms"`
	LossPct  float64 `json:"loss_pct"`
	Error    string  `json:"error,omitempty"`
}
