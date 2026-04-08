package api

import (
	"argus/internal/bgp"
	"argus/internal/bgpstate"
	"argus/internal/cfmapi"
	"argus/internal/config"
	"argus/internal/enrich"
	"argus/internal/flowstore"
	"argus/internal/pathfinder"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/yl2chen/cidranger"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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

var Geo *enrich.GeoIP
var Resolver *enrich.DNSResolver
var Ranger cidranger.Ranger
var DB *sql.DB
var TelemetryDB *sql.DB
var CFM *cfmapi.Client

// BGPMon is the session monitor (bgpstate.Monitor), set by main.go.
// Nil when RouterOS is not connected; handlers degrade gracefully.
var BGPMon bgpstate.Monitor

// RIB is the multi-path RIB watcher (bgpstate.RIBReader), set by main.go.
// Phase 1 stub: always returns empty entries. Populated by ROUTEWATCH.
var RIB bgpstate.RIBReader

var ipProfileRefresh = struct {
	mu         sync.Mutex
	refreshing map[string]bool
}{
	refreshing: make(map[string]bool),
}

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

func realIPAllowed(r *http.Request, cidrs []string) bool {
	ip := realIP(r)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
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

// realIP returns the true client IP.
// When the direct connection is from loopback (nginx proxying), it reads
// X-Forwarded-For to get the actual client address.
// XFF is only trusted from loopback — external clients cannot spoof it.
func realIP(r *http.Request) net.IP {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	directIP := net.ParseIP(host)

	if directIP != nil && directIP.IsLoopback() {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first := strings.TrimSpace(strings.Split(fwd, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				log.Printf("[AUTH] realIP: loopback→XFF=%s", ip)
				return ip
			}
		}
		log.Printf("[AUTH] realIP: loopback, no XFF")
		return directIP
	}
	log.Printf("[AUTH] realIP: direct=%s", directIP)
	return directIP
}

// WithAuth accepts if EITHER the source IP is allowed OR a valid Bearer token
// is present. This means:
//   - IPs in allow_ips (+ loopback) work with no token — dashboard, CLI, local
//   - External callers (CFM API etc.) can authenticate with token from anywhere
//   - When nginx sits in front, all requests arrive as 127.0.0.1 — no token needed

func WithAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if realIPAllowed(r, config.AppConfig.API.AllowIPs) {
			handler(w, r)
			return
		}
		// Bearer token
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
		// Session
		if sessionAllowed(r) {
			handler(w, r)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// WithMainIPOnly enforces IP allowlist only — no token.
// Used for telemetry, dashboard, debug pages, and pprof.
func WithMainIPOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if realIPAllowed(r, config.AppConfig.API.AllowIPs) {
			h(w, r)
			return
		}
		if sessionAllowed(r) {
			h(w, r)
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func WithMainIPOnlyHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if realIPAllowed(r, config.AppConfig.API.AllowIPs) {
			h.ServeHTTP(w, r)
			return
		}
		if sessionAllowed(r) {
			h.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// ── Start ─────────────────────────────────────────────────────────────────────

func Start() {
	mainMux := http.NewServeMux()
	startIPProfileCleanupJob()

	// ── Authenticated API endpoints ───────────────────────────────────────
	mainMux.HandleFunc("/infoip", WithAuth(handleInfoIP))
	mainMux.HandleFunc("/status", WithAuth(handleStatus))
	mainMux.HandleFunc("/communities", WithAuth(handleCommunities))
	mainMux.HandleFunc("/announce", WithAuth(handleAnnounce))
	mainMux.HandleFunc("/withdraw", WithAuth(handleWithdraw))
	mainMux.HandleFunc("/announcements", WithAuth(handleListAnnouncements))
	mainMux.HandleFunc("/bgpannouncements", WithAuth(handleAdjIn))
	mainMux.HandleFunc("/aspathviz", WithAuth(handleASPathViz))
	mainMux.HandleFunc("/bgpstatus", WithAuth(handleBGPStatus))
	mainMux.HandleFunc("/blackhole-list", WithAuth(handleBlackholeList))
	mainMux.HandleFunc("/blackhole-search", WithAuth(handleBlackholeSearch))
	mainMux.HandleFunc("/flush", WithAuth(handleFlush))
	mainMux.HandleFunc("/snmp/interfaces", WithAuth(handleSNMPInterfaces))

	// ── Telemetry — read-only, IP-only ────────────────────────────────────
	mainMux.HandleFunc("/tel/overview", WithMainIPOnly(handleTelOverview))
	mainMux.HandleFunc("/tel/timeseries", WithMainIPOnly(handleTelTimeSeries))
	mainMux.HandleFunc("/tel/asn", WithMainIPOnly(handleTelASN))
	mainMux.HandleFunc("/tel/sankey", WithMainIPOnly(handleTelSankey))
	mainMux.HandleFunc("/tel/hosts", WithMainIPOnly(handleTelHosts))
	mainMux.HandleFunc("/tel/ports", WithMainIPOnly(handleTelPorts))
	mainMux.HandleFunc("/tel/snapshots", WithMainIPOnly(handleTelSnapshots))
	mainMux.HandleFunc("/tel/snapshot", WithMainIPOnly(handleTelSnapshotGet))
	mainMux.HandleFunc("/tel/history", WithMainIPOnly(handleTelHistory))
	mainMux.HandleFunc("/tel/interfaces", WithMainIPOnly(handleTelInterfaces))
	mainMux.HandleFunc("/tel/iface-sankey", WithMainIPOnly(handleTelIfaceSankey))

	mainMux.HandleFunc("/api/risk",       WithMainIPOnly(handleRiskList))
	mainMux.HandleFunc("/risk",           WithMainIPOnly(handleRiskPage)) 

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
	mainMux.HandleFunc("/pathfinder/asn", WithMainIPOnly(handlePathfinderASN))
	mainMux.HandleFunc("/pathfinder/prefix", WithMainIPOnly(handlePathfinderPrefix))

	mainMux.HandleFunc("/pathfinder/ping", WithMainIPOnly(handlePathfinderPing))
	mainMux.HandleFunc("/pathfinder/traceroute", WithMainIPOnly(handlePathfinderTraceroute))

	mainMux.HandleFunc("/asn/{asn}", WithMainIPOnly(handleASNPage))
	mainMux.HandleFunc("/asn/{asn}/profile", WithMainIPOnly(handleASNProfile))
	mainMux.HandleFunc("/asn/{asn}/timeline", WithMainIPOnly(flowstore.HandleASNTimeline(DB)))
	mainMux.HandleFunc("/asn/{asn}/detail", WithMainIPOnly(flowstore.HandleASNDetail(DB)))
	mainMux.HandleFunc("/asn/{asn}/summary", WithMainIPOnly(flowstore.HandleASNSummary(DB)))
	mainMux.HandleFunc("/ip/{ip}", WithMainIPOnly(handleIPPage))
	mainMux.HandleFunc("/ip/{ip}/profile", WithMainIPOnly(handleIPProfile))

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

	mainMux.HandleFunc("/bgp/sessions", WithMainIPOnly(handleBGPSessions))
	mainMux.HandleFunc("/bgp/events", WithMainIPOnly(handleBGPEvents))
	mainMux.HandleFunc("/bgp/filters", WithMainIPOnly(handleBGPFilters))
	mainMux.HandleFunc("/bgp/originated", WithMainIPOnly(handleBGPOriginated))
	mainMux.HandleFunc("/bgp/advertisements", WithMainIPOnly(handleBGPAdvertisements))
	mainMux.HandleFunc("/bgp/received", WithMainIPOnly(handleBGPReceived))

	// ── RouterOS / BGP session monitoring ────────────────────────────────
	mainMux.HandleFunc("/routeros/bgp/sessions", WithMainIPOnly(handleROSBGPSessions))
	mainMux.HandleFunc("/routeros/bgp/peers", WithMainIPOnly(handleROSBGPPeers))
	mainMux.HandleFunc("/routeros/router/info", WithMainIPOnly(handleROSRouterInfo))

	// ── Dashboard & flow debug — IP-only ─────────────────────────────────
	mainMux.HandleFunc("/dashboard", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	}))
	mainMux.HandleFunc("/static/nav-search.js", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write(navSearchJS)
	}))
	mainMux.HandleFunc("/debug/flows", WithMainIPOnly(handleFlowsDebug))
	mainMux.HandleFunc("/tel/flows/stream", WithMainIPOnly(handleFlowsStream))
	mainMux.HandleFunc("/debug/rawflows", WithMainIPOnly(handleRawFlowsDebug))
	mainMux.HandleFunc("/tel/rawflows/stream", WithMainIPOnly(handleRawFlowsStream))

	// ── pprof — IP-only (loopback always permitted) ───────────────────────
	// Access from the server itself: curl http://127.0.0.1:9600/debug/pprof/
	// Access from a management host: must be in api.allow_ips
	mainMux.HandleFunc("/debug/pprof/", WithMainIPOnly(pprof.Index))
	mainMux.HandleFunc("/debug/pprof/cmdline", WithMainIPOnly(pprof.Cmdline))
	mainMux.HandleFunc("/debug/pprof/profile", WithMainIPOnly(pprof.Profile))
	mainMux.HandleFunc("/debug/pprof/symbol", WithMainIPOnly(pprof.Symbol))
	mainMux.HandleFunc("/debug/pprof/trace", WithMainIPOnly(pprof.Trace))
	mainMux.Handle("/debug/pprof/goroutine", WithMainIPOnlyHandler(pprof.Handler("goroutine")))
	mainMux.Handle("/debug/pprof/heap", WithMainIPOnlyHandler(pprof.Handler("heap")))
	mainMux.Handle("/debug/pprof/allocs", WithMainIPOnlyHandler(pprof.Handler("allocs")))
	mainMux.Handle("/debug/pprof/block", WithMainIPOnlyHandler(pprof.Handler("block")))
	mainMux.Handle("/debug/pprof/mutex", WithMainIPOnlyHandler(pprof.Handler("mutex")))
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

	// ── Auth endpoints — public, no IP/session guard ───────────────────────
	mainMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleLoginPage(w, r)
		case http.MethodPost:
			handleLoginAPI(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
	mainMux.HandleFunc("/logout", handleLogout)

	// Stack: panic recovery → global IP/rate/ban guard → mux routing → per-route auth
	// LoadAndSave must be outermost so the session is available to all
	// middleware beneath it (including WithMainIPOnly's sessionAllowed check).
	inner := withRecovery(globalGuard(mainMux))
	var handler http.Handler = inner
	if Auth != nil {
		handler = Auth.LoadAndSave(inner)
	}

	apiAddr := fmt.Sprintf("%s:%d", config.AppConfig.API.ListenAddress, config.AppConfig.API.Port)
	srv := &http.Server{
		Addr:              apiAddr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second, // slow-loris protection
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
	includeTrace := r.URL.Query().Get("traceroute") == "1"
	res, status, err := buildIPProfileResponse(r.Context(), ipStr, includeTrace)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func handleIPProfile(w http.ResponseWriter, r *http.Request) {
	ipStr := strings.TrimSpace(r.PathValue("ip"))
	includeTrace := r.URL.Query().Get("traceroute") == "1"
	res, status, err := buildIPProfileResponse(r.Context(), ipStr, includeTrace)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func buildIPProfileResponse(ctx context.Context, ipStr string, includeTrace bool) (map[string]interface{}, int, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, http.StatusBadRequest, fmt.Errorf("Invalid IP")
	}
	now := time.Now()
	res := map[string]interface{}{"ip": ipStr}
	staleAfter := 24 * time.Hour
	if config.AppConfig != nil && config.AppConfig.IPProfile.StaleAfter > 0 {
		staleAfter = config.AppConfig.IPProfile.StaleAfter
	}

	cacheRow, fresh, err := lookupFreshIPProfile(ipStr, now, staleAfter)
	if err != nil {
		log.Printf("[WARN] ip_profile lookup failed ip=%s err=%v", ipStr, err)
	}
	sourceStatus := map[string]map[string]interface{}{
		"cache": {"ok": err == nil, "hit": fresh && cacheRow != nil},
	}
	if fresh && cacheRow != nil {
		asn, _ := strconv.ParseUint(strings.TrimSpace(cacheRow.ASN), 10, 32)
		res["ptr"] = cacheRow.PTR
		res["asn"] = uint32(asn)
		res["asn_name"] = cacheRow.ASNName
		res["country"] = cacheRow.Country
		res["cache"] = map[string]interface{}{
			"hit":        true,
			"hits":       cacheRow.Hits,
			"updated_at": cacheRow.UpdatedAt,
			"first_seen": cacheRow.FirstSeen,
			"last_seen":  cacheRow.LastSeen,
		}
		sourceStatus["cache"]["stale"] = false
		sourceStatus["ptr"] = map[string]interface{}{"ok": true, "from_cache": true}
		sourceStatus["geo"] = map[string]interface{}{"ok": true, "from_cache": true}
	} else if cacheRow != nil {
		asn, _ := strconv.ParseUint(strings.TrimSpace(cacheRow.ASN), 10, 32)
		res["ptr"] = cacheRow.PTR
		res["asn"] = uint32(asn)
		res["asn_name"] = cacheRow.ASNName
		res["country"] = cacheRow.Country
		res["cache"] = map[string]interface{}{
			"hit":        true,
			"stale":      true,
			"hits":       cacheRow.Hits,
			"updated_at": cacheRow.UpdatedAt,
			"first_seen": cacheRow.FirstSeen,
			"last_seen":  cacheRow.LastSeen,
		}
		sourceStatus["cache"] = map[string]interface{}{"ok": true, "hit": true, "stale": true}
		sourceStatus["ptr"] = map[string]interface{}{"ok": true, "from_cache": true, "stale": true}
		sourceStatus["geo"] = map[string]interface{}{"ok": true, "from_cache": true, "stale": true}
		refreshIPProfileAsync(ipStr)
	} else {
		ptr, asn, asnName, country, providerStatus := resolveIPProviders(ipStr)
		res["ptr"] = ptr
		res["asn"] = asn
		res["asn_name"] = asnName
		res["country"] = country
		sourceStatus["ptr"] = providerStatus["ptr"]
		sourceStatus["geo"] = providerStatus["geo"]

		row := &ipProfileRow{
			IP:      ipStr,
			ASN:     strconv.FormatUint(uint64(asn), 10),
			ASNName: asnName,
			Country: country,
			PTR:     ptr,
		}
		if err := upsertIPProfile(row, now); err != nil {
			log.Printf("[WARN] ip_profile upsert failed ip=%s err=%v", ipStr, err)
		}
		res["cache"] = map[string]interface{}{
			"hit":   false,
			"stale": cacheRow != nil,
		}
		sourceStatus["cache"]["stale"] = cacheRow != nil
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
				hops := buildASPathHops(bgpEntry.ASPath)
				res["as_path"] = hops
				var comms []string
				for _, c := range bgpEntry.Communities {
					comms = append(comms, fmt.Sprintf("%d:%d", c>>16, c&0xFFFF))
				}
				res["communities"] = comms
			}
		}
	}
	if event, err := fetchLatestBlackholeEvent(ipStr); err != nil {
		log.Printf("[WARN] blackhole history lookup failed ip=%s err=%v", ipStr, err)
	} else {
		res["blackhole"] = map[string]interface{}{
			"active":       event != nil && event["is_active"] == true,
			"latest_event": event,
		}
	}
	if history, err := fetchIPDetectionsHistory(ipStr, 20); err != nil {
		log.Printf("[WARN] detections history lookup failed ip=%s err=%v", ipStr, err)
	} else {
		res["detections"] = history
	}

if riskEvents, err := fetchIPRiskEvents(ipStr, 50); err != nil {
		log.Printf("[WARN] risk_events lookup failed ip=%s err=%v", ipStr, err)
	} else {
		res["risk_events"] = riskEvents
	}

	res["routing"] = buildRoutingContext(ctx, ip, res["prefix"], includeTrace)


	res["routing"] = buildRoutingContext(ctx, ip, res["prefix"], includeTrace)
	res["external_links"] = buildASNExternalLinks(res["asn"])
	res["source_status"] = sourceStatus
	return res, http.StatusOK, nil
}

func resolveIPProviders(ipStr string) (ptr string, asn uint32, asnName string, country string, status map[string]map[string]interface{}) {
	status = map[string]map[string]interface{}{
		"ptr": {"ok": Resolver != nil},
		"geo": {"ok": Geo != nil},
	}
	startPTR := time.Now()
	if Resolver != nil {
		ptr = Resolver.LookupPTR(ipStr)
	}
	status["ptr"]["latency_ms"] = time.Since(startPTR).Milliseconds()

	startGeo := time.Now()
	if Geo != nil {
		asn = Geo.GetASNNumber(ipStr)
		asnName = Geo.GetASNName(ipStr)
		country = Geo.GetCountry(ipStr)
	}
	status["geo"]["latency_ms"] = time.Since(startGeo).Milliseconds()
	return ptr, asn, asnName, country, status
}

func refreshIPProfileAsync(ipStr string) {
	ipProfileRefresh.mu.Lock()
	if ipProfileRefresh.refreshing[ipStr] {
		ipProfileRefresh.mu.Unlock()
		return
	}
	ipProfileRefresh.refreshing[ipStr] = true
	ipProfileRefresh.mu.Unlock()

	go func() {
		defer func() {
			ipProfileRefresh.mu.Lock()
			delete(ipProfileRefresh.refreshing, ipStr)
			ipProfileRefresh.mu.Unlock()
		}()
		start := time.Now()
		ptr, asn, asnName, country, status := resolveIPProviders(ipStr)
		row := &ipProfileRow{
			IP:      ipStr,
			ASN:     strconv.FormatUint(uint64(asn), 10),
			ASNName: asnName,
			Country: country,
			PTR:     ptr,
		}
		if err := upsertIPProfile(row, time.Now()); err != nil {
			log.Printf(`{"component":"ip_profile","event":"async_refresh","ip":%q,"ok":false,"latency_ms":%d,"error":%q}`, ipStr, time.Since(start).Milliseconds(), err.Error())
			return
		}
		geoOK, _ := status["geo"]["ok"].(bool)
		ptrOK, _ := status["ptr"]["ok"].(bool)
		log.Printf(`{"component":"ip_profile","event":"async_refresh","ip":%q,"ok":true,"latency_ms":%d,"geo_ok":%t,"ptr_ok":%t}`, ipStr, time.Since(start).Milliseconds(), geoOK, ptrOK)
	}()
}

func buildRoutingContext(ctx context.Context, ip net.IP, prefixVal interface{}, includeTrace bool) map[string]interface{} {
	routing := map[string]interface{}{
		"prefix":           "",
		"best_as_path":     []map[string]string{},
		"pathfinder":       map[string]interface{}{},
		"traceroute":       map[string]interface{}{"available": PathfinderROSClient != nil, "requested": includeTrace},
		"routeros_enabled": PathfinderROSClient != nil,
	}
	prefix, _ := prefixVal.(string)
	if strings.TrimSpace(prefix) == "" {
		return routing
	}
	routing["prefix"] = prefix

	if asPath, ok := RangerBestASPath(ip); ok {
		routing["best_as_path"] = asPath
	}

	if PathfinderResolver == nil {
		return routing
	}

	resolved, err := PathfinderResolver.ResolvePrefix(prefix)
	if err != nil || resolved == nil {
		return routing
	}
	pf := map[string]interface{}{}
	if resolved.BestPath != nil {
		pf["best"] = map[string]interface{}{
			"next_hop":   resolved.BestPath.NextHop,
			"upstream":   resolved.BestPath.Upstream,
			"hops":       len(resolved.BestPath.ASPath),
			"as_path":    resolved.BestPath.ASPath,
			"local_pref": resolved.BestPath.LocalPref,
			"peer_asn":   resolved.BestPath.PeerASN,
		}
	}
	if PathfinderROSClient != nil {
		rosCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		routes, err := PathfinderROSClient.ListDetailedRoutesByPrefix(rosCtx, prefix)
		if err == nil && len(routes) > 0 {
			addrCtx, addrCancel := context.WithTimeout(ctx, 3*time.Second)
			addrs, _ := PathfinderROSClient.ListIPAddresses(addrCtx)
			addrCancel()
			summaries := rosRoutesToSummary(routes, addrs)
			pf["routes"] = summaries
			if includeTrace {
				trace := tracerouteSummaryForIP(ctx, ip.String(), summaries)
				routing["traceroute"] = trace
			}
		}
	}
	routing["pathfinder"] = pf
	return routing
}

func RangerBestASPath(ip net.IP) ([]map[string]string, bool) {
	if Ranger == nil {
		return nil, false
	}
	entries, err := Ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return nil, false
	}
	longest := entries[0]
	for _, e := range entries {
		if lenMask(e.Network().Mask) > lenMask(longest.Network().Mask) {
			longest = e
		}
	}
	bgpEntry, ok := longest.(bgp.BGPEnrichedEntry)
	if !ok {
		return nil, false
	}
	return buildASPathHops(bgpEntry.ASPath), true
}

func tracerouteSummaryForIP(ctx context.Context, ip string, routes []pathfinder.RouteSummary) map[string]interface{} {
	out := map[string]interface{}{
		"available": PathfinderROSClient != nil,
		"requested": true,
	}
	if PathfinderROSClient == nil {
		return out
	}
	var chosen *pathfinder.RouteSummary
	for i := range routes {
		if routes[i].Active {
			chosen = &routes[i]
			break
		}
	}
	if chosen == nil && len(routes) > 0 {
		chosen = &routes[0]
	}
	if chosen == nil {
		out["error"] = "no route candidates available"
		return out
	}
	out["source_ip"] = chosen.LocalIP
	out["upstream"] = chosen.Upstream
	out["next_hop"] = chosen.Gateway
	traceCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	hops, err := PathfinderROSClient.Traceroute(traceCtx, ip, chosen.LocalIP)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["hop_count"] = len(hops)
	if len(hops) > 0 {
		out["first_hop"] = hops[0].Address
		out["last_hop"] = hops[len(hops)-1].Address
	}
	out["hops"] = hops
	return out
}

func buildASNExternalLinks(asnVal interface{}) []map[string]string {
	asnNum, ok := asnVal.(uint32)
	if !ok || asnNum == 0 {
		return []map[string]string{}
	}
	asn := strconv.FormatUint(uint64(asnNum), 10)
	return []map[string]string{
		{"label": "BGP.HE", "url": "https://bgp.he.net/AS" + asn},
		{"label": "BGP Tools", "url": "https://bgp.tools/as/" + asn},
		{"label": "RIPEstat", "url": "https://stat.ripe.net/AS" + asn},
		{"label": "PeeringDB", "url": "https://www.peeringdb.com/asn/" + asn},
		{"label": "Cloudflare Radar", "url": "https://radar.cloudflare.com/as" + asn},
	}
}

func buildASPathHops(path []string) []map[string]string {
	hops := make([]map[string]string, 0, len(path))
	for _, hopASN := range path {
		hops = append(hops, map[string]string{
			"asn":      hopASN,
			"asn_name": resolveASNLabel(hopASN),
			// Country is an IP GeoIP field and isn't meaningful for ASN-only hops.
			"country": "unsupported",
		})
	}
	return hops
}

func resolveASNLabel(asn string) string {
	n, err := strconv.ParseUint(strings.TrimSpace(asn), 10, 32)
	if err != nil {
		return "AS" + asn
	}
	asn32 := uint32(n)

	if config.AppConfig != nil {
		if name, ok := config.AppConfig.Pathfinder.TransitASNMap[asn32]; ok && strings.TrimSpace(name) != "" {
			return name
		}
	}

	if DB != nil {
		if meta, err := flowstore.QueryMeta(DB, asn32); err == nil && meta != nil {
			if strings.TrimSpace(meta.ASNName) != "" {
				return meta.ASNName
			}
		}
	}

	return fmt.Sprintf("AS%d", asn32)
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
			if peer.State.Messages.Received != nil {
				msgIn = peer.State.Messages.Received.Total
			}
			if peer.State.Messages.Sent != nil {
				msgOut = peer.State.Messages.Sent.Total
			}
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

// handleASNPage serves the per-ASN drill-down page.
// asnHTML is embedded in embed.go alongside dashboardHTML, pathfinderHTML, etc.
func handleASNPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(asnHTML)
}

func handleIPPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(ipHTML)
}

func handleRiskPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(detectionHTML)
}

// handleRiskList serves GET /api/risk.
// Returns one row per unique source IP, aggregated over the last 7 days,
// sorted by peak fused score descending.
func handleRiskList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if DB == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()

	rows, err := DB.Query(`
		SELECT
			src,
			COUNT(*)        AS event_count,
			MAX(fused)      AS peak_fused,
			MAX(ts)         AS last_seen,
			MIN(ts)         AS first_seen,
			asn,
			asn_name,
			cc,
			ptr,
			(SELECT shape       FROM risk_events r2
			 WHERE r2.src = r1.src ORDER BY ts DESC LIMIT 1) AS latest_shape,
			(SELECT example_dst FROM risk_events r2
			 WHERE r2.src = r1.src ORDER BY ts DESC LIMIT 1) AS latest_dst,
			(SELECT ex_count    FROM risk_events r2
			 WHERE r2.src = r1.src ORDER BY ts DESC LIMIT 1) AS latest_ex_count
		FROM risk_events r1
		WHERE ts > ?
		GROUP BY src
		ORDER BY peak_fused DESC
		LIMIT 200
	`, cutoff)
	if err != nil {
		log.Printf("[WARN] handleRiskList query failed: %v", err)
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type riskRow struct {
		Src          string  `json:"src"`
		EventCount   int64   `json:"event_count"`
		PeakFused    float64 `json:"peak_fused"`
		LastSeen     int64   `json:"last_seen"`
		FirstSeen    int64   `json:"first_seen"`
		ASN          int64   `json:"asn"`
		ASNName      string  `json:"asn_name"`
		CC           string  `json:"cc"`
		PTR          string  `json:"ptr"`
		LatestShape  string  `json:"latest_shape"`
		LatestDst    string  `json:"latest_dst"`
		LatestExCount int64  `json:"latest_ex_count"`
	}

	out := make([]riskRow, 0)
	for rows.Next() {
		var row riskRow
		var asn, eventCount, lastSeen, firstSeen, latestExCount sql.NullInt64
		var peakFused sql.NullFloat64
		var asnName, cc, ptr, latestShape, latestDst sql.NullString

		if err := rows.Scan(
			&row.Src, &eventCount, &peakFused, &lastSeen, &firstSeen,
			&asn, &asnName, &cc, &ptr,
			&latestShape, &latestDst, &latestExCount,
		); err != nil {
			log.Printf("[WARN] handleRiskList scan failed: %v", err)
			continue
		}
		row.EventCount   = eventCount.Int64
		row.PeakFused    = peakFused.Float64
		row.LastSeen     = lastSeen.Int64
		row.FirstSeen    = firstSeen.Int64
		row.ASN          = asn.Int64
		row.ASNName      = asnName.String
		row.CC           = cc.String
		row.PTR          = ptr.String
		row.LatestShape  = latestShape.String
		row.LatestDst    = latestDst.String
		row.LatestExCount = latestExCount.Int64
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[WARN] handleRiskList rows.Err: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"risk_ips":    out,
		"count":       len(out),
		"window_days": 7,
	})
}
