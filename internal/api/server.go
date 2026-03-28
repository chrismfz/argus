package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/pprof"
	"argus/internal/enrich"
	"argus/internal/bgp"
	"github.com/yl2chen/cidranger"
	"log"
	"fmt"
	"sort"
	"time"
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

// ── Middleware ────────────────────────────────────────────────────────────────

// WithMainIPOnly allows access based on IP only (no token required).
// Used for read-only telemetry and dashboard routes.
func WithMainIPOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(r, config.AppConfig.API.AllowIPs) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// shared helper used by both middlewares
func ipAllowed(r *http.Request, cidrs []string) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if c == "127.0.0.1" && ip.IsLoopback() {
			return true
		}
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
		if net.ParseIP(c) != nil && ip.Equal(net.ParseIP(c)) {
			return true
		}
	}
	return false
}

// For generic http.Handler (needed by pprof.Handler(...))
func WithIPAllowOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(r, config.AppConfig.DebugAPI.AllowIPs) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Adapter to use WithAuth(func) with http.Handler too
func WithAuthHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WithAuth(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		})(w, r)
	})
}

// For HandlerFunc
func WithIPAllowOnlyFunc(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !ipAllowed(r, config.AppConfig.DebugAPI.AllowIPs) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// ── Start ─────────────────────────────────────────────────────────────────────

func Start() {
	// --- Main API mux (token + IP protected via WithAuth) ---
	mainMux := http.NewServeMux()
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

	// Telemetry — read-only, IP-only (no token required)
	mainMux.HandleFunc("/tel/overview",   WithMainIPOnly(handleTelOverview))
	mainMux.HandleFunc("/tel/timeseries", WithMainIPOnly(handleTelTimeSeries))
	mainMux.HandleFunc("/tel/asn",        WithMainIPOnly(handleTelASN))
	mainMux.HandleFunc("/tel/sankey",     WithMainIPOnly(handleTelSankey))
	mainMux.HandleFunc("/tel/hosts",      WithMainIPOnly(handleTelHosts))
	mainMux.HandleFunc("/tel/ports",      WithMainIPOnly(handleTelPorts))
	mainMux.HandleFunc("/tel/snapshots",  WithMainIPOnly(handleTelSnapshots))
	mainMux.HandleFunc("/tel/snapshot",   WithMainIPOnly(handleTelSnapshotGet))
	mainMux.HandleFunc("/tel/history",    WithMainIPOnly(handleTelHistory))

	// Dashboard HTML — IP-only, no token
	mainMux.HandleFunc("/dashboard", WithMainIPOnly(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	}))

	apiAddr := fmt.Sprintf("%s:%d", config.AppConfig.API.ListenAddress, config.AppConfig.API.Port)
	mainSrv := &http.Server{
		Addr:              apiAddr,
		Handler:           mainMux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("[API] Listening on %s", apiAddr)
		if err := mainSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[API] ListenAndServe: %v", err)
		}
	}()

	// --- Debug/pprof mux (separate port) ---
	if config.AppConfig.DebugAPI.Enabled {
		dbgMux := http.NewServeMux()

		var guardFunc    func(http.HandlerFunc) http.HandlerFunc
		var guardHandler func(http.Handler) http.Handler
		if config.AppConfig.DebugAPI.RequireToken {
			guardFunc    = WithAuth
			guardHandler = WithAuthHandler
		} else {
			guardFunc    = WithIPAllowOnlyFunc
			guardHandler = WithIPAllowOnly
		}

		dbgMux.HandleFunc("/debug/pprof/",          guardFunc(pprof.Index))
		dbgMux.HandleFunc("/debug/pprof/cmdline",   guardFunc(pprof.Cmdline))
		dbgMux.HandleFunc("/debug/pprof/profile",   guardFunc(pprof.Profile))
		dbgMux.HandleFunc("/debug/pprof/symbol",    guardFunc(pprof.Symbol))
		dbgMux.HandleFunc("/debug/pprof/trace",     guardFunc(pprof.Trace))

		dbgMux.Handle("/debug/pprof/goroutine",     guardHandler(pprof.Handler("goroutine")))
		dbgMux.Handle("/debug/pprof/heap",          guardHandler(pprof.Handler("heap")))
		dbgMux.Handle("/debug/pprof/allocs",        guardHandler(pprof.Handler("allocs")))
		dbgMux.Handle("/debug/pprof/block",         guardHandler(pprof.Handler("block")))
		dbgMux.Handle("/debug/pprof/mutex",         guardHandler(pprof.Handler("mutex")))
		dbgMux.Handle("/debug/pprof/threadcreate",  guardHandler(pprof.Handler("threadcreate")))

		dbgAddr := fmt.Sprintf("%s:%d", config.AppConfig.DebugAPI.ListenAddress, config.AppConfig.DebugAPI.Port)
		dbgSrv := &http.Server{
			Addr:              dbgAddr,
			Handler:           dbgMux,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}

		go func() {
			log.Printf("[API][debug] pprof listening on %s", dbgAddr)
			if err := dbgSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[API][debug] ListenAndServe: %v", err)
			}
		}()
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
	status := map[string]bool{
		"infoip":   Geo != nil,
		"resolver": Resolver != nil,
		"bgp":      Ranger != nil,
	}
	json.NewEncoder(w).Encode(status)
}

func handleCommunities(w http.ResponseWriter, r *http.Request) {
	set := make(map[string]struct{})

	if Ranger != nil {
		entries, err := Ranger.CoveredNetworks(net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		})
		if err == nil {
			for _, e := range entries {
				if bgpEntry, ok := e.(bgp.BGPEnrichedEntry); ok {
					for _, c := range bgpEntry.Communities {
						comStr := fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)
						set[comStr] = struct{}{}
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

		uptime := ""
		if peer.Timers != nil && peer.Timers.State != nil && peer.Timers.State.Uptime != nil {
			uptime = time.Since(peer.Timers.State.Uptime.AsTime()).Round(time.Second).String()
		}

		lastDown := ""
		if peer.Timers != nil && peer.Timers.State != nil && peer.Timers.State.Downtime != nil {
			lastDown = peer.Timers.State.Downtime.AsTime().Local().Format("2006-01-02 15:04:05")
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
			IP:          peer.Conf.NeighborAddress,
			RemoteASN:   peer.Conf.PeerAsn,
			State:       state,
			Uptime:      uptime,
			LastDown:    lastDown,
			MessagesIn:  msgIn,
			MessagesOut: msgOut,
			AFISAFI:     afiSafi,
		})
	})

	if err != nil {
		http.Error(w, "Failed to get peer status", http.StatusInternalServerError)
		return
	}

	summary := map[string]interface{}{
		"total_peers":        totalPeers,
		"established_peers":  establishedPeers,
		"prefixes_announced": len(bgp.ListAnnouncements()),
		"prefixes_received":  bgp.GetPathCount(),
		"peers":              peers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
