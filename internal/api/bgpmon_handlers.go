package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"argus/internal/bgp"
	"argus/internal/bgpmon"
	"argus/internal/bgpstate"
	"argus/internal/routeros"
)

// ── GET /bgp/sessions ────────────────────────────────────────────────────────
//
// Returns the current session snapshot with summary and reachability flag.
// Prefers BGPMon in-memory state (always current). Falls back to reading
// the last-known state from SQLite when BGPMon is nil (RouterOS was down at
// startup) so the UI still has something to show.
//
// Response shape:
//
//	{
//	  "reachable":  true,
//	  "last_poll":  1234567890,
//	  "summary":    { "total": 10, "established": 10, "down": 0 },
//	  "sessions":   [ ...SessionStatus... ]
//	}
func handleBGPSessions(w http.ResponseWriter, r *http.Request) {
	var sessions []bgpstate.SessionStatus
	var reachable bool
	var lastPoll int64

	if BGPMon != nil {
		sessions = BGPMon.Sessions()
		reachable = BGPMon.Reachable()
		lastPoll = BGPMon.LastPoll()
	} else {
		// BGPMon not started (RouterOS unavailable at startup).
		// Return whatever is in the DB from a previous run.
		if DB != nil {
			var err error
			sessions, err = bgpmon.ListSessionStates(DB)
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		reachable = false
	}

	if sessions == nil {
		sessions = []bgpstate.SessionStatus{}
	}

	jsonOK(w, map[string]interface{}{
		"reachable": reachable,
		"last_poll": lastPoll,
		"summary":   bgpstate.Summarise(sessions),
		"sessions":  sessions,
	})
}

// ── GET /bgp/events ──────────────────────────────────────────────────────────
//
// Returns recent BGP session events, newest first.
//
// Query params:
//   - limit   int    max rows (default 100, cap 500)
//   - session string if set, filter to this session name only
func handleBGPEvents(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	session := r.URL.Query().Get("session")

	events, err := bgpmon.ListEvents(DB, limit, session)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []bgpstate.SessionEvent{}
	}

	jsonOK(w, map[string]interface{}{
		"events":  events,
		"session": session, // echo back so the UI knows what it received
	})
}

// ── GET /bgp/filters ─────────────────────────────────────────────────────────
//
// Returns routing filter rules and BGP connection configs from RouterOS.
// Used by the BGP cockpit Peers & Filters tab to show:
//   - which filter chains exist and what they do
//   - which chains are applied (input/output) on each peer connection
//
// Response shape:
//
//	{
//	  "rules":       [ ...FilterRule...  ],
//	  "connections": [ ...BGPPeer...     ]
//	}
func handleBGPFilters(w http.ResponseWriter, r *http.Request) {
	if PathfinderROSClient == nil {
		jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	rules, err := PathfinderROSClient.ListFilterRules(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "filter rules: "+err.Error())
		return
	}
	if rules == nil {
		rules = []routeros.FilterRule{}
	}

	peers, err := PathfinderROSClient.ListBGPPeers(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "connections: "+err.Error())
		return
	}
	if peers == nil {
		peers = []routeros.BGPPeer{}
	}

	jsonOK(w, map[string]interface{}{
		"rules":       rules,
		"connections": peers,
	})
}

// ── GET /bgp/originated ──────────────────────────────────────────────────────
//
// Returns the prefixes currently announced by Argus's embedded GoBGP speaker
// (active blackhole /32s and any other originated routes).
//
// These are routes Argus originated — NOT what it received from peers.
// For inbound paths, use /pathfinder/prefix.
//
// Response shape:
//
//	{
//	  "prefixes": [ ...AnnouncedPrefix... ]
//	}
func handleBGPOriginated(w http.ResponseWriter, r *http.Request) {
	prefixes := bgp.GetAnnouncedPrefixes()
	if prefixes == nil {
		prefixes = []bgp.AnnouncedPrefix{}
	}
	jsonOK(w, map[string]interface{}{
		"prefixes": prefixes,
	})
}


// GET /bgp/advertisements?peer=<session-name>
//
// Returns the prefixes MikroTik is currently advertising to the named peer,
// sourced from /rest/routing/bgp/advertisements on RouterOS.
// peer is required — omitting it would return the full table (potentially very large).
func handleBGPAdvertisements(w http.ResponseWriter, r *http.Request) {
	if PathfinderROSClient == nil {
		jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
		return
	}
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		jsonErr(w, http.StatusBadRequest, "missing ?peer=")
		return
	}
 
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
 
	ads, err := PathfinderROSClient.ListBGPAdvertisements(ctx, peer)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ads == nil {
		ads = []routeros.BGPAdvertisement{}
	}
	jsonOK(w, map[string]interface{}{
		"peer":           peer,
		"count":          len(ads),
		"advertisements": ads,
	})
}



// GET /bgp/received?session=<session-name>
//
// Returns the prefixes received from a specific BGP peer, sourced from
// RouterOS /routing/route filtered by the session's belongs-to identifier.
//
// The belongs-to format is "bgp-IP-<remoteIP>" for IPv4 sessions and
// "bgp-IPv6-<remoteIP>" for IPv6 sessions (RouterOS internal process name).
//
// Timeout is 30s — full-table peers (Synapsecom, HE) have 1M+ routes.
// The UI warns before calling for peers with prefixes_rx > 5000.
func handleBGPReceived(w http.ResponseWriter, r *http.Request) {
	if PathfinderROSClient == nil {
		jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
		return
	}
	if BGPMon == nil {
		jsonErr(w, http.StatusServiceUnavailable, "BGP monitor not ready")
		return
	}
	sessionName := r.URL.Query().Get("session")
	if sessionName == "" {
		jsonErr(w, http.StatusBadRequest, "missing ?session=")
		return
	}
 
	// Look up session to get remote IP and AFI.
	sess, ok := BGPMon.SessionByName(sessionName)
	if !ok {
		jsonErr(w, http.StatusNotFound, "session not found: "+sessionName)
		return
	}
 
	// RouterOS internal process name for this session's routes.
	// IPv6 peers use "bgp-IPv6-<ip>", IPv4 peers use "bgp-IP-<ip>".
	belongsTo := "bgp-IP-" + sess.RemoteAddress
	if sess.AFI == "ipv6" {
		belongsTo = "bgp-IPv6-" + sess.RemoteAddress
	}
 
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
 
	routes, err := PathfinderROSClient.ListPeerRoutes(ctx, belongsTo)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if routes == nil {
		routes = []routeros.ReceivedRoute{}
	}
 
	jsonOK(w, map[string]interface{}{
		"session":    sessionName,
		"remote":     sess.RemoteAddress,
		"belongs_to": belongsTo,
		"count":      len(routes),
		"routes":     routes,
	})
}
