// Package bgpstate defines the shared types and interfaces for all BGP subsystems
// in Argus: bgpmon (session monitoring), rib (multi-path RIB), and routewatch
// (path health / blackhole detection).
//
// This package has zero logic and zero external dependencies beyond the standard
// library. It is the contract layer — every BGP subsystem depends on bgpstate,
// and no BGP subsystem depends on another directly.
//
// Dependency graph (intended):
//
//	bgpstate          ← this package
//	  ↑
//	  ├── bgpmon      (implements bgpstate.Monitor; source = RouterOS REST)
//	  ├── rib         (implements bgpstate.RIBReader; source = GoBGP adj-in)
//	  └── routewatch  (consumes bgpstate.Monitor + bgpstate.RIBReader)
package bgpstate

import "time"

// ── Session types ─────────────────────────────────────────────────────────────

// SessionStatus is the live state of one BGP session.
//
// Produced by bgpmon.Monitor on every poll cycle and written to SQLite.
// Consumed by ROUTEWATCH to verify session health before acting on path data
// (e.g. "is the Synapsecom session actually up before I probe via it?").
type SessionStatus struct {
	Name           string `json:"name"`
	Comment        string `json:"comment"`         // human label e.g. "Synapsecom", "GR-IX"
	RemoteAS       uint32 `json:"remote_as"`
	RemoteASName   string `json:"remote_as_name"`  // resolved via MaxMind from RemoteAddress
	RemoteAddress  string `json:"remote_address"`
	LocalAddress   string `json:"local_address"`
	AFI            string `json:"afi"`             // "ip" | "ipv6"
	State          string `json:"state"`           // "established" | "idle" | "unknown"
	Established    bool   `json:"established"`
	UptimeRaw      string `json:"uptime_raw"`      // RouterOS format e.g. "2w6d13h"
	PrefixesRx     int    `json:"prefixes_rx"`
	PrefixesTx     int    `json:"prefixes_tx"`
	LastSeen       int64  `json:"last_seen"`       // unix timestamp of last successful poll
	ConnectionName string `json:"connection_name"` // links to /routing/bgp/connection
}

// SessionSummary is the aggregate health snapshot for the /bgp/sessions response.
type SessionSummary struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	Down        int `json:"down"`
}

// Summarise computes aggregate counts from a slice of SessionStatus values.
// Sessions in state "unknown" (RouterOS unreachable) are not counted as down.
func Summarise(sessions []SessionStatus) SessionSummary {
	s := SessionSummary{Total: len(sessions)}
	for _, sess := range sessions {
		switch {
		case sess.Established:
			s.Established++
		case sess.State == "idle" || sess.State == "active":
			s.Down++
		}
	}
	return s
}

// ── Event types ───────────────────────────────────────────────────────────────

// EventKind is the type of a BGP event recorded in the event log.
//
// bgpmon uses the Session* constants.
// routewatch uses the Path* constants.
//
// The type is an open string alias — subsystems may define additional values
// without modifying this file.
type EventKind string

const (
	// Session lifecycle events (bgpmon)
	EventEstablished   EventKind = "established"   // session came up (first seen or recovered)
	EventDown          EventKind = "down"           // established → idle/unknown
	EventFlap          EventKind = "flap"           // established → established with uptime reset
	EventRecovered     EventKind = "recovered"      // idle/unknown → established
	EventUnreachable   EventKind = "unreachable"    // RouterOS REST API unreachable
	EventRESTRecovered EventKind = "rest_recovered" // RouterOS REST API back online

	// Path health events (routewatch Phase 1)
	EventBlackholeDetected  EventKind = "blackhole_detected"  // active path broken, alt path ok
	EventBlackholeCleared   EventKind = "blackhole_cleared"   // blackhole resolved
	EventGeneralOutage      EventKind = "general_outage"      // all paths failing
	EventMitigationApplied  EventKind = "mitigation_applied"  // filter rule injected on MikroTik
	EventMitigationReverted EventKind = "mitigation_reverted" // filter rule removed

	// Path quality events (routewatch Phase 2)
	EventPathSwitched EventKind = "path_switched" // best path changed due to scoring
)

// SessionEvent is one entry in the BGP event log (bgp_session_events table).
//
// bgpmon writes these on every state transition.
// ROUTEWATCH may read recent events for context (e.g. "was this session
// flapping before the blackhole appeared?").
type SessionEvent struct {
	ID           int64     `json:"id"`
	Timestamp    int64     `json:"ts"`                      // unix seconds
	Session      string    `json:"session"`                 // session name
	RemoteAS     uint32    `json:"remote_as"`
	Kind         EventKind `json:"event"`
	FromState    string    `json:"from_state,omitempty"`
	ToState      string    `json:"to_state,omitempty"`
	UptimeBefore string    `json:"uptime_before,omitempty"` // uptime just before going down
	Detail       string    `json:"detail,omitempty"`        // free text, e.g. error message
}

// ── Path / RIB types ─────────────────────────────────────────────────────────

// PathInfo is one BGP path learned from a peer.
//
// Used in two contexts:
//
//  1. BGP cockpit Prefix Lookup tab — display only. Probe and score fields
//     will be zero/nil.
//
//  2. ROUTEWATCH PrefixState — the monitor fills ProbeIP/ProbeOK/RTTms during
//     Phase 1, and Score during Phase 2. The BGP cockpit can surface these
//     values if present, but does not depend on them.
//
// Using a single type avoids a conversion layer between the cockpit and
// routewatch — a PrefixEntry from rib.Watcher can be passed directly to
// either consumer.
type PathInfo struct {
	// ── Routing ──────────────────────────────────────────────────────────────

	NextHop   string `json:"next_hop"`
	Interface string `json:"interface,omitempty"` // e.g. "sfp1-Synapsecom"
	Upstream  string `json:"upstream,omitempty"`  // human label derived from Interface

	// ── BGP attributes ───────────────────────────────────────────────────────

	ASPath           []uint32 `json:"as_path,omitempty"`
	LocalPref        uint32   `json:"local_pref,omitempty"`
	MED              int      `json:"med,omitempty"`
	Communities      []string `json:"communities,omitempty"`
	LargeCommunities []string `json:"large_communities,omitempty"`
	Origin           string   `json:"origin,omitempty"` // "igp" | "egp" | "incomplete"

	// ── Session context ───────────────────────────────────────────────────────

	LearnedFrom string    `json:"learned_from,omitempty"` // session name e.g. "AS8280-1"
	LearnedAt   time.Time `json:"learned_at,omitempty"`
	IsBest      bool      `json:"is_best"`

	// ── ROUTEWATCH Phase 1 — probe results ───────────────────────────────────
	// Zero-valued until rib.Watcher / routewatch populates them.
	// The BGP cockpit hides these fields in the UI when ProbeOK is nil.

	ProbeIP string  `json:"probe_ip,omitempty"`
	ProbeOK *bool   `json:"probe_ok,omitempty"` // nil = not yet probed
	RTTms   float64 `json:"rtt_ms,omitempty"`

	// ── ROUTEWATCH Phase 2 — path quality score ───────────────────────────────
	// Zero until scorer.go populates it.
	// Lower score = better path (see ROUTEWATCH scoring formula).

	Score float64 `json:"score,omitempty"`
}

// PrefixEntry holds all known paths for one prefix.
//
// Produced by rib.Watcher (which subscribes to GoBGP adj-in).
// Consumed by:
//   - BGP cockpit Prefix Lookup tab (display all paths with attributes)
//   - ROUTEWATCH blackhole detection (compare active vs alt paths, probe both)
//
// The Probe* fields below are ROUTEWATCH state layered on top of the RIB entry.
// rib.Watcher leaves them zero; routewatch.Watcher fills them in-place on the
// same struct so both cockpit and routewatch always see the latest state.
type PrefixEntry struct {
	Prefix     string     `json:"prefix"`
	ActivePath *PathInfo  `json:"active_path,omitempty"`
	AltPaths   []PathInfo `json:"alt_paths,omitempty"`
	LastUpdate time.Time  `json:"last_update"`

	// ROUTEWATCH Phase 1 probe state — zero until routewatch fills it.
	ProbeIP     string    `json:"probe_ip,omitempty"`
	ProbeStatus string    `json:"probe_status,omitempty"` // "ok" | "fail" | "unknown"
	FailCount   int       `json:"fail_count,omitempty"`
	LastCheck   time.Time `json:"last_check,omitempty"`
	LastAlert   time.Time `json:"last_alert,omitempty"`
}

// AllPaths returns ActivePath (if set) followed by all AltPaths.
// Convenience helper used by both the cockpit and routewatch prober.
func (e *PrefixEntry) AllPaths() []PathInfo {
	var out []PathInfo
	if e.ActivePath != nil {
		out = append(out, *e.ActivePath)
	}
	out = append(out, e.AltPaths...)
	return out
}

// HasAltPath returns true if at least one alternative path exists.
// ROUTEWATCH uses this to decide whether probing makes sense
// (no point detecting a blackhole if there is nowhere to fail over to).
func (e *PrefixEntry) HasAltPath() bool {
	return len(e.AltPaths) > 0
}
