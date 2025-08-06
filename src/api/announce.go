package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"net"
	"flowenricher/bgp"
	"flowenricher/config"
	"context"
	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgppkt "github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type AnnouncedPrefix struct {
	Prefix      string   `json:"prefix"`
	NextHop     string   `json:"next_hop"`
	Communities []string `json:"communities"`
	Timestamp   time.Time `json:"timestamp"`
	ASPath []uint32 `json:"as_path,omitempty"`
	IsBlackhole bool `json:"blackhole"`
}


func handleAnnounce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AnnouncedPrefix
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate prefix
	if req.Prefix == "" {
		http.Error(w, "Prefix is required", http.StatusBadRequest)
		return
	}

	// Optional: validate nextHop if set
	if req.NextHop != "" && net.ParseIP(req.NextHop) == nil {
		http.Error(w, "Invalid next_hop IP", http.StatusBadRequest)
		return
	}

	if req.NextHop == "" {
		if bgp.LocalBGPAddress != "" {
			req.NextHop = bgp.LocalBGPAddress
		} else {
			req.NextHop = "127.0.0.1"
		}
	}

asn := config.GetLocalASN()
req.ASPath = []uint32{asn}



	err := bgp.AnnouncePrefix(req.Prefix, req.NextHop, req.Communities, req.ASPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to announce: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Announced %s\n", req.Prefix)
}

func handleWithdraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Prefix string `json:"prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := bgp.WithdrawPrefix(req.Prefix)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to withdraw: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Withdrawn %s\n", req.Prefix)
}




func handleListAnnouncements(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ipQuery := r.URL.Query().Get("ip")
	all := bgp.ListAnnouncements()

	// Αν δόθηκε IP ως query param
	if ipQuery != "" {
		ip := net.ParseIP(ipQuery)
		if ip == nil {
			http.Error(w, "Invalid IP", http.StatusBadRequest)
			return
		}

		prefix := fmt.Sprintf("%s/32", ip.String())
		if ann, ok := all[prefix]; ok {
			json.NewEncoder(w).Encode(map[string]bgp.AnnouncedPrefix{
				prefix: ann,
			})
		} else {
			// Δεν βρέθηκε
			json.NewEncoder(w).Encode(map[string]any{})
		}
		return
	}

	// Κανονικά: επιστρέφει όλα
	json.NewEncoder(w).Encode(all)
}





type AdjInEntry struct {
    Prefix      string   `json:"prefix"`
    ASPath      []uint32 `json:"as_path,omitempty"`
    Communities []string `json:"communities,omitempty"`
}


func handleAdjIn(w http.ResponseWriter, r *http.Request) {
    results := make(map[string][]map[string]interface{})

    err := bgp.AnnounceServer.ListPeer(context.Background(), &apipb.ListPeerRequest{}, func(peer *apipb.Peer) {
        for _, rf := range []bgppkt.RouteFamily{bgppkt.RF_IPv4_UC, bgppkt.RF_IPv6_UC} {
            afi, safi := bgppkt.RouteFamilyToAfiSafi(rf)
            family := &apipb.Family{
                Afi:  apipb.Family_Afi(afi),
                Safi: apipb.Family_Safi(safi),
            }

            _ = bgp.AnnounceServer.ListPath(context.Background(), &apipb.ListPathRequest{
                Family:    family,
                Name:      peer.Conf.NeighborAddress,
                TableType: apipb.TableType_ADJ_IN,
            }, func(dest *apipb.Destination) {
                for _, p := range dest.Paths {
                    entry := map[string]interface{}{}

                    nlri, _ := apiutil.UnmarshalNLRI(rf, p.Nlri)
                    if prefix, ok := nlri.(bgppkt.AddrPrefixInterface); ok {
                        entry["prefix"] = prefix.String()
                    }

                    // Parse attributes
                    if attrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs); err == nil {
                        for _, attr := range attrs {
                            switch v := attr.(type) {
                            case *bgppkt.PathAttributeAsPath:
                                var asns []uint32
                                for _, seg := range v.Value {
                                    switch s := seg.(type) {
                                    case *bgppkt.As4PathParam:
                                        asns = append(asns, s.AS...)
                                    case *bgppkt.AsPathParam:
                                        for _, asn := range s.AS {
                                            asns = append(asns, uint32(asn))
                                        }
                                    }
                                }
                                entry["as_path"] = asns

                            case *bgppkt.PathAttributeCommunities:
                                var comms []string
                                for _, c := range v.Value {
                                    comms = append(comms, fmt.Sprintf("%d:%d", c>>16, c&0xFFFF))
                                }
                                entry["communities"] = comms
                            }
                        }
                    }

                    results[peer.Conf.NeighborAddress] = append(results[peer.Conf.NeighborAddress], entry)
                }
            })
        }
    })

    if err != nil {
        http.Error(w, "Failed to list adj-in paths", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(results)
}








func handleASPathViz(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		http.Error(w, "Missing ?ip= query param", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}

	if Ranger == nil {
		http.Error(w, "BGP data not loaded", http.StatusServiceUnavailable)
		return
	}

	entries, err := Ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		http.Error(w, "Prefix not found", http.StatusNotFound)
		return
	}

	// Πάρε το πιο μακρύ match
	longest := entries[0]
	for _, e := range entries {
		if lenMask(e.Network().Mask) > lenMask(longest.Network().Mask) {
			longest = e
		}
	}

	bgpEntry, ok := longest.(bgp.BGPEnrichedEntry)
	if !ok {
		http.Error(w, "Invalid entry format", http.StatusInternalServerError)
		return
	}

	// Δημιούργησε απλή JSON απεικόνιση path
	type Hop struct {
		ASN      string `json:"asn"`
		ASNName  string `json:"asn_name,omitempty"`
		Country  string `json:"country,omitempty"`
	}

	var hops []Hop
	for _, asn := range bgpEntry.ASPath {
		hops = append(hops, Hop{
			ASN:     asn,
			ASNName: Geo.GetASNName(asn),
			Country: Geo.GetCountry(asn),
		})
	}

netCopy := longest.Network()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":      ipStr,
		"prefix":  (&netCopy).String(), // ✅
		"as_path": hops,
	})
}
