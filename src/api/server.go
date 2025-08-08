package api

import (
	"context"                               // ✅ Add this
	"encoding/json"
	"net"
	"net/http"
	"flowenricher/enrich"
        "flowenricher/bgp"
	"github.com/yl2chen/cidranger"
	"log"
	"fmt"
	"sort"
	"time"                                   // ✅ Add this
	apipb "github.com/osrg/gobgp/v3/api"     // ✅ Add this
	"database/sql"
	"flowenricher/config"
)

type GeoIPResponse struct {
	IP       string   `json:"ip"`
	PTR      string   `json:"ptr,omitempty"`
	ASN      uint32   `json:"asn,omitempty"`
	ASNName  string   `json:"asn_name,omitempty"`
	Country  string   `json:"country,omitempty"`
	ASPath   []string `json:"as_path,omitempty"`
	Communities []string `json:"communities,omitempty"` // ✅ νέο
}

// Πρέπει να τους κάνεις pass απ’ το main
var Geo *enrich.GeoIP
var Resolver *enrich.DNSResolver
var Ranger cidranger.Ranger
var DB *sql.DB // για SQLite access

func Start() {

http.HandleFunc("/infoip", WithAuth(handleInfoIP))
http.HandleFunc("/status", WithAuth(handleStatus))
http.HandleFunc("/communities", WithAuth(handleCommunities))
http.HandleFunc("/announce", WithAuth(handleAnnounce))
http.HandleFunc("/withdraw", WithAuth(handleWithdraw))
http.HandleFunc("/announcements", WithAuth(handleListAnnouncements))
http.HandleFunc("/bgpannouncements", WithAuth(handleAdjIn))
http.HandleFunc("/aspathviz", WithAuth(handleASPathViz))
http.HandleFunc("/bgpstatus", WithAuth(handleBGPStatus))
http.HandleFunc("/blackhole-list", WithAuth(handleBlackholeList))
http.HandleFunc("/flush", WithAuth(handleFlush))

http.HandleFunc("/snmp/interfaces", WithAuth(handleSNMPInterfaces))


listenAddr := fmt.Sprintf("%s:%d", config.AppConfig.API.ListenAddress, config.AppConfig.API.Port)
log.Printf("[API] Listening on %s", listenAddr)
if err := http.ListenAndServe(listenAddr, nil); err != nil {

		log.Fatalf("[API] ListenAndServe error: %v", err)
	}

}




func handleInfoIP(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}

	res := map[string]interface{}{
		"ip":      ipStr,
		"ptr":     Resolver.LookupPTR(ipStr),
		"asn":     Geo.GetASNNumber(ipStr),
		"asn_name": Geo.GetASNName(ipStr),
		"country": Geo.GetCountry(ipStr),
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
	netCopy := longest.Network()                      // ✅ Add this
	res["prefix"] = netCopy.String()                  // ✅ Fix this line

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
		"infoip":    Geo != nil,
		"resolver": Resolver != nil,
		"bgp":      Ranger != nil,
	}
	json.NewEncoder(w).Encode(status)
}


// list communities
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
		IP         string `json:"ip"`
		RemoteASN  uint32 `json:"remote_as"`
		State      string `json:"state"`
		Uptime     string `json:"uptime,omitempty"`
		LastDown   string `json:"last_downtime,omitempty"`
		MessagesIn  uint64 `json:"messages_received"`
		MessagesOut uint64 `json:"messages_sent"`
		AFISAFI    []string `json:"afi_safi"`
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
			IP:         peer.Conf.NeighborAddress,
			RemoteASN:  peer.Conf.PeerAsn,
			State:      state,
			Uptime:     uptime,
			LastDown:   lastDown,
			MessagesIn: msgIn,
			MessagesOut: msgOut,
			AFISAFI:    afiSafi,
		})
	})

	if err != nil {
		http.Error(w, "Failed to get peer status", http.StatusInternalServerError)
		return
	}

	summary := map[string]interface{}{
		"total_peers":          totalPeers,
		"established_peers":    establishedPeers,
		"prefixes_announced":   len(bgp.ListAnnouncements()),
		"prefixes_received":    bgp.GetPathCount(), // ✅ We'll add this next
		"peers":                peers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
