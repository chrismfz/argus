package api

import (
	"encoding/json"
	"net"
	"net/http"
	"flowenricher/enrich"
        "flowenricher/bgp"
	"github.com/yl2chen/cidranger"
	"log"
	"fmt"
	"sort"
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


func Start() {
	http.HandleFunc("/geoip", handleGeoIP)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/communities", handleCommunities)

http.HandleFunc("/announce", handleAnnounce)
http.HandleFunc("/withdraw", handleWithdraw)
http.HandleFunc("/announcements", handleListAnnouncements)
http.HandleFunc("/bgpannouncements", handleAdjIn)
http.HandleFunc("/aspathviz", handleASPathViz)


	log.Println("[API] Listening on 127.0.0.1:9600")
	if err := http.ListenAndServe("127.0.0.1:9600", nil); err != nil {
		log.Fatalf("[API] ListenAndServe error: %v", err)
	}
}


func handleGeoIP(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}

	res := GeoIPResponse{
		IP:      ipStr,
		PTR:     Resolver.LookupPTR(ipStr),
		ASN:     Geo.GetASNNumber(ipStr),
		ASNName: Geo.GetASNName(ipStr),
		Country: Geo.GetCountry(ipStr),
	}



	// Lookup σε BGP Ranger για AS Path

if Ranger != nil {
	if entries, err := Ranger.ContainingNetworks(ip); err == nil && len(entries) > 0 {
		longest := entries[0]
		for _, e := range entries {
			if lenMask(e.Network().Mask) > lenMask(longest.Network().Mask) {
				longest = e
			}
		}
		if bgpEntry, ok := longest.(bgp.BGPEnrichedEntry); ok {
			res.ASPath = bgpEntry.ASPath
			for _, c := range bgpEntry.Communities {
				comStr := fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)
				res.Communities = append(res.Communities, comStr)
			}
		}
	}
}




	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}




func lenMask(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}



func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]bool{
		"geoip":    Geo != nil,
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
