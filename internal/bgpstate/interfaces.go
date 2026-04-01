package bgpstate

// Monitor is implemented by bgpmon.Monitor.
//
// ROUTEWATCH imports this interface — never bgpmon directly — to check session
// health without creating a circular dependency. The concrete *bgpmon.Monitor
// is passed in from main.go via dependency injection.
//
// Usage in main.go:
//
//	mon := bgpmon.New(db, rosClient, alerter.Global, geo)
//	go mon.Run(ctx)
//	api.BGPMon = mon              // api expects bgpstate.Monitor
//	routewatch.New(..., mon, ...) // routewatch expects bgpstate.Monitor
type Monitor interface {
	// Sessions returns the current live state of all known BGP sessions.
	// The returned slice is a snapshot — safe to read without holding any lock.
	Sessions() []SessionStatus

	// SessionByName returns the current state of a single session.
	// Returns false if the session is not known.
	SessionByName(name string) (SessionStatus, bool)

	// Reachable reports whether the RouterOS REST API was reachable on the last poll.
	// When false, all session states are "unknown" and path data should be treated
	// with suspicion by ROUTEWATCH.
	Reachable() bool

	// LastPoll returns the unix timestamp of the most recent completed poll cycle.
	LastPoll() int64
}

// RIBReader is implemented by rib.Watcher.
//
// Both the BGP cockpit Prefix Lookup handler and ROUTEWATCH consume this
// interface. The cockpit uses it to show all paths for a prefix. ROUTEWATCH
// uses it as the source of PrefixEntry.ActivePath / AltPaths for blackhole
// detection.
//
// rib.Watcher is the only implementation today. When ROUTEWATCH begins,
// it receives the same *rib.Watcher that was already constructed in main.go —
// no additional wiring needed.
type RIBReader interface {
	// GetPrefix returns the current PrefixEntry for a given CIDR string.
	// Returns false if the prefix is not in the RIB.
	GetPrefix(prefix string) (*PrefixEntry, bool)

	// GetPrefixesForASN returns all PrefixEntries whose ActivePath originates
	// from (or passes through) the given ASN. Used by the cockpit Prefix Lookup
	// and by ROUTEWATCH when building the watchlist.
	GetPrefixesForASN(asn uint32) []PrefixEntry

	// Snapshot returns a point-in-time copy of the entire multi-path RIB,
	// keyed by prefix string. Used by ROUTEWATCH for periodic diff-based
	// change detection (complements the pathfinder.RIBSnapshot which only
	// holds best paths).
	Snapshot() map[string]PrefixEntry
}

// UpstreamLabeler resolves a human-readable upstream name from BGP path attributes.
// Satisfied by *pathfinder.UpstreamMap without any changes to that package.
//
// Declared here so rib.Watcher can accept an upstream resolver without importing
// internal/pathfinder, which would create a circular dependency
// (pathfinder → rib → pathfinder).
//
// Pass nil if upstream labeling is not needed — all consumers must degrade
// gracefully (Upstream field stays empty string).
type UpstreamLabeler interface {
	Resolve(communities []string, asPath []uint32, nextHop string) string
}

// GeoLookup is satisfied by *enrich.GeoIP (GetASNName method already exists).
//
// Declared here so bgpmon and routewatch can accept a geo enricher without
// importing the full internal/enrich package, eliminating any risk of a
// circular import.
//
// Pass nil if geo is unavailable — all consumers must degrade gracefully
// (ASN name stays empty string, alerts omit the parenthetical).
type GeoLookup interface {
	GetASNName(ip string) string
}
