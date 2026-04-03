package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/pprof"
	"argus/internal/enrich"
	"argus/internal/bgp"
	"argus/internal/bgpstate"
	"github.com/yl2chen/cidranger"
	"log"
	"fmt"
	"sort"
	"time"
	"strings"
	apipb "github.com/osrg/gobgp/v3/api"
	"database/sql"
	"argus/internal/config"
	"argus/internal/cfmapi"
)

type GeoIPResponse struct {
	IP          string   `json:"ip"`
	PTR         string   `json:"ptr,omitempty"`
	ASN         uint32   `json:"asn,omitempty"`
	ASNName     string   `json:"asn_name,omitempty"`
	Country     string   `json:"country,omitempty"`
	ASPath      []string `json:"as_path,omitempty"`
	Communities []string `json:"communities,omitempty"`
}

var Geo         *enrich.GeoIP
var Resolver    *enrich.DNSResolver
var Ranger      cidranger.Ranger
var DB          *sql.DB
var TelemetryDB *sql.DB
var CFM         *cfmapi.Client

// BGPMon is the session monitor (bgpstate.Monitor), set by main.go.
// Nil when RouterOS is not connected; handlers degrade gracefully.
var BGPMon bgpstate.Monitor

// RIB is the multi-path RIB watcher (bgpstate.RIBReader), set by main.go.
// Phase 1 stub: always returns empty entries. Populated by ROUTEWATCH.
var RIB bgpstate.RIBReader

// ── Middleware ────────────────────────────────────────────────────────────────

// ipAllowed checks the request's remote IP against a CIDR/IP list.
// Loopback addresses are always permitted.
func ipAllowed(r *http.Request, cidrs []string) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true // 127.x.x.x / ::1 always allowed
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
		if net.ParseIP(c) != nil && ip.Equal(net.ParseIP(c)) {
			return true
		}
	}
	return false
}

// WithAuth accepts if EITHER the source IP is allowed OR a valid Bearer token
// is present. This means:
//   - IPs in allow_ips (+ loopback) work with no token — dashboard, CLI, local
//   - External callers (CFM API etc.) can authenticate with token from anywhere
//   - When nginx sits in front, all requests arrive as 127.0.0.1 — no token needed
func WithAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// IP allowed — let through immediately
		if ipAllowed(r, config.AppConfig.API.AllowIPs) {
			handler(w, r)
			return
		}
		// Not an allowed IP — try Bearer token
		if len(config.AppConfig.API.Tokens) > 0 {
			if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
				token := auth[7:]
				for _, t := range config.AppConfig.API.Tokens {
					if token == t {
						handler(w, r)
						return
					}
				}
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// WithMainIPOnly enforces IP allowlist only — no token.
// Used for telemetry, dashboard, debug pages, and pprof.
func WithMainIPOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(r, config.AppConfig.API.AllowIPs) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// WithMainIPOnlyHandler wraps an http.Handler (needed for pprof.Handler(...)).
func WithMainIPOnlyHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(r, config.AppConfig.API.AllowIPs) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ── Start ─────────────────────────────────────────────────────────────────────

func Start() {
	mainMux := http.NewServeMux()

	// ── Authenticated API endpoints ───────────────────────────────────────
	mainMux.HandleFunc("/infoip",           WithAuth(handleInfoIP))
	mainMux.HandleFunc("/status",           WithAuth(handleStatus))
	mainMux.HandleFunc("/communities",      WithAuth(handleCommunities))
	mainMux.HandleFunc("/announce",         WithAuth(handleAnnounce))
	mainMux.HandleFunc("/withdraw",         WithAuth(handleWithdraw))
	mainMux.HandleFunc("/announcements",    WithAuth(handleListAnnouncements))
	mainMux.HandleFunc("/bgpannouncements", WithAuth(handleAdjIn))
	mainMux.HandleFunc("/aspathviz",        WithAuth(handleASPathViz))
	mainMux.HandleFunc("/bgpstatus",        WithAuth(handleBGPStatus))
	mainMux.HandleFunc("/blackhole-list",   WithAuth(handleBlackholeList))
	mainMux.HandleFunc("/blackhole-search", WithAuth(handleBlackholeSearch))
	mainMux.HandleFunc("/flush",            WithAuth(handleFlush))
	mainMux.HandleFunc("/snmp/interfaces",  WithAuth(handleSNMPInterfaces))

	// ── Telemetry — read-only, IP-only ────────────────────────────────────
	mainMux.HandleFunc("/tel/overview",     WithMainIPOnly(handleTelOverview))
	mainMux.HandleFunc("/tel/timeseries",   WithMainIPOnly(handleTelTimeSeries))
	mainMux.HandleFunc("/tel/asn",          WithMainIPOnly(handleTelASN))
	mainMux.HandleFunc("/tel/sankey",       WithMainIPOnly(handleTelSankey))
	mainMux.HandleFunc("/tel/hosts",        WithMainIPOnly(handleTelHosts))
	mainMux.HandleFunc("/tel/ports",        WithMainIPOnly(handleTelPorts))
	mainMux.HandleFunc("/tel/snapshots",    WithMainIPOnly(handleTelSnapshots))
	mainMux.HandleFunc("/tel/snapshot",     WithMainIPOnly(handleTelSnapshotGet))
	mainMux.HandleFunc("/tel/history",      WithMainIPOnly(handleTelHistory))
	mainMux.HandleFunc("/tel/interfaces",   WithMainIPOnly(handleTelInterfaces))
	mainMux.HandleFunc("/tel/iface-sankey", WithMainIPOnly(handleTelIfaceSankey))

	// ── Alerter page ──────────────────────────────────────────────────────
	mainMux.HandleFunc("/alerts", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(alertsHTML)
	}))

	// ── Alerter contacts CRUD ─────────────────────────────────────────────
	mainMux.HandleFunc("/alerter/contacts", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAlerterContactsList(w, r)
		case http.MethodPost:
			handleAlerterContactsCreate(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	// /alerter/contacts/{id}  /alerter/contacts/{id}/test  /alerter/contacts/{id}/toggle
	mainMux.HandleFunc("/alerter/contacts/", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/test") && r.Method == http.MethodPost:
			handleAlerterContactsTest(w, r)
		case strings.HasSuffix(path, "/toggle") && r.Method == http.MethodPatch:
			handleAlerterContactsToggle(w, r)
		case r.Method == http.MethodPut:
			handleAlerterContactsUpdate(w, r)
		case r.Method == http.MethodDelete:
			handleAlerterContactsDelete(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	// ── Alerter events & stats ────────────────────────────────────────────
	// /stats must be registered before /events to avoid prefix conflict
	mainMux.HandleFunc("/alerter/events/stats", WithMainIPOnly(handleAlerterEventsStats))
	mainMux.HandleFunc("/alerter/events", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAlerterEventsList(w, r)
		case http.MethodDelete:
			handleAlerterEventsClear(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	// ── Alerter SSE live feed ─────────────────────────────────────────────
	// nginx: needs its own location block with proxy_buffering off
	mainMux.HandleFunc("/alerter/stream", WithMainIPOnly(handleAlerterStream))


  // ── Pathfinder — BGP path intelligence ───────────────────────────────
  mainMux.HandleFunc("/pathfinder", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      w.Write(pathfinderHTML)
  }))
  mainMux.HandleFunc("/pathfinder/asn",    WithMainIPOnly(handlePathfinderASN))
  mainMux.HandleFunc("/pathfinder/prefix", WithMainIPOnly(handlePathfinderPrefix))

mainMux.HandleFunc("/pathfinder/ping", WithMainIPOnly(handlePathfinderPing))
mainMux.HandleFunc("/pathfinder/traceroute", WithMainIPOnly(handlePathfinderTraceroute))


  // ── BGP cockpit ──────────────────────────────────────────────────────
  mainMux.HandleFunc("/bgp", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      w.Write(bgpHTML)
  }))

  mainMux.HandleFunc("/routewatch", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      w.Write(routewatchHTML)
  }))
  mainMux.HandleFunc("/routewatch/status", WithMainIPOnly(handleRouteWatchStatus))


  mainMux.HandleFunc("/bgp/sessions",   WithMainIPOnly(handleBGPSessions))
  mainMux.HandleFunc("/bgp/events",     WithMainIPOnly(handleBGPEvents))
  mainMux.HandleFunc("/bgp/filters",    WithMainIPOnly(handleBGPFilters))
  mainMux.HandleFunc("/bgp/originated", WithMainIPOnly(handleBGPOriginated))
  mainMux.HandleFunc("/bgp/advertisements",WithMainIPOnly(handleBGPAdvertisements))

  // ── RouterOS / BGP session monitoring ────────────────────────────────
  mainMux.HandleFunc("/routeros/bgp/sessions", WithMainIPOnly(handleROSBGPSessions))
  mainMux.HandleFunc("/routeros/bgp/peers",    WithMainIPOnly(handleROSBGPPeers))
  mainMux.HandleFunc("/routeros/router/info",  WithMainIPOnly(handleROSRouterInfo))

	// ── Dashboard & flow debug — IP-only ─────────────────────────────────
	mainMux.HandleFunc("/dashboard", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	}))
	mainMux.HandleFunc("/debug/flows",         WithMainIPOnly(handleFlowsDebug))
	mainMux.HandleFunc("/tel/flows/stream",    WithMainIPOnly(handleFlowsStream))
	mainMux.HandleFunc("/debug/rawflows",      WithMainIPOnly(handleRawFlowsDebug))
	mainMux.HandleFunc("/tel/rawflows/stream", WithMainIPOnly(handleRawFlowsStream))

	// ── pprof — IP-only (loopback always permitted) ───────────────────────
	// Access from the server itself: curl http://127.0.0.1:9600/debug/pprof/
	// Access from a management host: must be in api.allow_ips
	mainMux.HandleFunc("/debug/pprof/",         WithMainIPOnly(pprof.Index))
	mainMux.HandleFunc("/debug/pprof/cmdline",  WithMainIPOnly(pprof.Cmdline))
	mainMux.HandleFunc("/debug/pprof/profile",  WithMainIPOnly(pprof.Profile))
	mainMux.HandleFunc("/debug/pprof/symbol",   WithMainIPOnly(pprof.Symbol))
	mainMux.HandleFunc("/debug/pprof/trace",    WithMainIPOnly(pprof.Trace))
	mainMux.Handle("/debug/pprof/goroutine",    WithMainIPOnlyHandler(pprof.Handler("goroutine")))
	mainMux.Handle("/debug/pprof/heap",         WithMainIPOnlyHandler(pprof.Handler("heap")))
	mainMux.Handle("/debug/pprof/allocs",       WithMainIPOnlyHandler(pprof.Handler("allocs")))
	mainMux.Handle("/debug/pprof/block",        WithMainIPOnlyHandler(pprof.Handler("block")))
	mainMux.Handle("/debug/pprof/mutex",        WithMainIPOnlyHandler(pprof.Handler("mutex")))
	mainMux.Handle("/debug/pprof/threadcreate", WithMainIPOnlyHandler(pprof.Handler("threadcreate")))

	// Catch-all: unknown paths → 403 (don't leak route map to scanners)
	mainMux.HandleFunc("/", notFoundHandler)


	// ── Detection settings page & API ─────────────────────────────────────
	mainMux.HandleFunc("/detection", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(detectionHTML)
	}))
	// List / add  (no trailing slash)
	mainMux.HandleFunc("/detection/excludes", WithAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleDetectionExcludesList(w, r)
		case http.MethodPost:
			handleDetectionExcludesAdd(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	// Single entry (delete / update)  — /detection/excludes/{id}
	mainMux.HandleFunc("/detection/excludes/", WithAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			handleDetectionExcludesDelete(w, r)
		case http.MethodPut:
			handleDetectionExcludesUpdate(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	// Stack: panic recovery → global IP/rate/ban guard → mux routing → per-route auth
	handler := withRecovery(globalGuard(mainMux))

	apiAddr := fmt.Sprintf("%s:%d", config.AppConfig.API.ListenAddress, config.AppConfig.API.Port)
	srv := &http.Server{
		Addr:              apiAddr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,  // slow-loris protection
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      30 * time.Second, // pprof profile can take 30s
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10, // 8 KiB headers — reject oversized header floods
	}

	log.Printf("[API] Listening on %s", apiAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[API] ListenAndServe: %v", err)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleInfoIP(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}
	res := map[string]interface{}{
		"ip":       ipStr,
		"ptr":      Resolver.LookupPTR(ipStr),
		"asn":      Geo.GetASNNumber(ipStr),
		"asn_name": Geo.GetASNName(ipStr),
		"country":  Geo.GetCountry(ipStr),
	}
	if Ranger != nil {
		if entries, err := Ranger.ContainingNetworks(ip); err == nil && len(entries) > 0 {
			longest := entries[0]
			for _, e := range entries {
				if lenMask(e.Network().Mask) > lenMask(longest.Network().Mask) {
					longest = e
				}
			}
			if bgpEntry, ok := longest.(bgp.BGPEnrichedEntry); ok {
				netCopy := longest.Network()
				res["prefix"] = netCopy.String()
				var hops []map[string]string
				for _, asn := range bgpEntry.ASPath {
					hops = append(hops, map[string]string{
						"asn":      asn,
						"asn_name": Geo.GetASNName(asn),
						"country":  Geo.GetCountry(asn),
					})
				}
				res["as_path"] = hops
				var comms []string
				for _, c := range bgpEntry.Communities {
					comms = append(comms, fmt.Sprintf("%d:%d", c>>16, c&0xFFFF))
				}
				res["communities"] = comms
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func lenMask(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]bool{
		"infoip":   Geo != nil,
		"resolver": Resolver != nil,
		"bgp":      Ranger != nil,
	})
}

func handleCommunities(w http.ResponseWriter, r *http.Request) {
	set := make(map[string]struct{})
	if Ranger != nil {
		entries, err := Ranger.CoveredNetworks(net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
		if err == nil {
			for _, e := range entries {
				if bgpEntry, ok := e.(bgp.BGPEnrichedEntry); ok {
					for _, c := range bgpEntry.Communities {
						set[fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)] = struct{}{}
					}
				}
			}
		}
	}
	var result []string
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleBGPStatus(w http.ResponseWriter, r *http.Request) {
	if bgp.AnnounceServer == nil {
		http.Error(w, "BGP server not initialized", http.StatusServiceUnavailable)
		return
	}
	type PeerStatus struct {
		IP          string   `json:"ip"`
		RemoteASN   uint32   `json:"remote_as"`
		State       string   `json:"state"`
		Uptime      string   `json:"uptime,omitempty"`
		LastDown    string   `json:"last_downtime,omitempty"`
		MessagesIn  uint64   `json:"messages_received"`
		MessagesOut uint64   `json:"messages_sent"`
		AFISAFI     []string `json:"afi_safi"`
	}
	var peers []PeerStatus
	var totalPeers, establishedPeers int
	err := bgp.AnnounceServer.ListPeer(context.Background(), &apipb.ListPeerRequest{}, func(peer *apipb.Peer) {
		totalPeers++
		state := peer.State.SessionState.String()
		if peer.State.SessionState == apipb.PeerState_ESTABLISHED {
			establishedPeers++
		}
		uptime, lastDown := "", ""
		if peer.Timers != nil && peer.Timers.State != nil {
			if peer.Timers.State.Uptime != nil {
				uptime = time.Since(peer.Timers.State.Uptime.AsTime()).Round(time.Second).String()
			}
			if peer.Timers.State.Downtime != nil {
				lastDown = peer.Timers.State.Downtime.AsTime().Local().Format("2006-01-02 15:04:05")
			}
		}
		afiSafi := []string{}
		for _, afi := range peer.AfiSafis {
			if afi.Config != nil && afi.Config.Family != nil {
				afiSafi = append(afiSafi, fmt.Sprintf("%s/%s", afi.Config.Family.Afi, afi.Config.Family.Safi))
			}
		}
		msgIn, msgOut := uint64(0), uint64(0)
		if peer.State.Messages != nil {
			if peer.State.Messages.Received != nil { msgIn = peer.State.Messages.Received.Total }
			if peer.State.Messages.Sent != nil { msgOut = peer.State.Messages.Sent.Total }
		}
		peers = append(peers, PeerStatus{
			IP: peer.Conf.NeighborAddress, RemoteASN: peer.Conf.PeerAsn,
			State: state, Uptime: uptime, LastDown: lastDown,
			MessagesIn: msgIn, MessagesOut: msgOut, AFISAFI: afiSafi,
		})
	})
	if err != nil {
		http.Error(w, "Failed to get peer status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_peers":        totalPeers,
		"established_peers":  establishedPeers,
		"prefixes_announced": len(bgp.ListAnnouncements()),
		"prefixes_received":  bgp.GetPathCount(),
		"peers":              peers,
	})
}
