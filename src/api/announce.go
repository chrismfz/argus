package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"net"
	"strings"
	"flowenricher/bgp"
	"flowenricher/config"
//	"flowenricher/detection"
	"context"
	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgppkt "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"log"
	"database/sql"
 "strconv" // <- Make sure this is imported
)

type AnnouncedPrefix struct {
	Prefix      string   `json:"prefix"`
	NextHop     string   `json:"next_hop"`
	Communities []string `json:"communities"`
	Timestamp   time.Time `json:"timestamp"`
	ASPath []uint32 `json:"as_path,omitempty"`
	IsBlackhole bool `json:"blackhole"`
	DurationSeconds int `json:"duration_seconds,omitempty"` // 
}


type BlackholeList struct {
	Prefix      string     `json:"prefix"`
	NextHop     string     `json:"next_hop,omitempty"`
	Communities []string   `json:"communities,omitempty"`
	Timestamp   time.Time  `json:"timestamp"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	ASPath      []uint32   `json:"as_path,omitempty"`

	ASN     uint32 `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
	Country string `json:"country,omitempty"`
	PTR     string `json:"ptr,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
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


// SQLite logging (αν DB υπάρχει)
if DB != nil {
	ip := strings.Split(req.Prefix, "/")[0]
	ptr := Resolver.LookupPTR(ip)
	asn := Geo.GetASNNumber(ip)
	asnName := Geo.GetASNName(ip)
	country := Geo.GetCountry(ip)

	ttl := time.Duration(req.DurationSeconds) * time.Second
	if ttl == 0 {
		ttl = 1 * time.Hour // default TTL
	}
	now := time.Now()
	expires := now.Add(ttl)

	_, err := DB.Exec(`
		INSERT OR REPLACE INTO blackholes
		(prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Prefix, now.Format(time.RFC3339), expires.Format(time.RFC3339), "(api)", "(manual)", asn, asnName, country, ptr)

	if err != nil {
		log.Printf("[WARN] Failed to insert into blackholes DB: %v", err)
	}
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


if DB != nil {
	_, err := DB.Exec(`DELETE FROM blackholes WHERE prefix = ?`, req.Prefix)
	if err != nil {
		log.Printf("[WARN] Failed to delete from blackholes DB: %v", err)
	}
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




func handleBlackholeList(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    if DB == nil {
        http.Error(w, "DB not initialized", http.StatusInternalServerError)
        return
    }

    rows, err := DB.Query(`
        SELECT prefix, timestamp, expires_at, rule, reason, asn, asn_name, country, ptr
        FROM blackholes
    `)
    if err != nil {
        http.Error(w, fmt.Sprintf("DB error: %v", err), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    result := make(map[string]BlackholeList)

    for rows.Next() {
        var b BlackholeList
        var ts, expires sql.NullString
        var rule, reason, asn, asnName, country, ptr sql.NullString

        err := rows.Scan(&b.Prefix, &ts, &expires, &rule, &reason, &asn, &asnName, &country, &ptr)
        if err != nil {
            log.Printf("[ERROR] Failed to scan row: %v", err)
            continue
        }

        if ts.Valid {
            if t, err := time.Parse(time.RFC3339, ts.String); err == nil {
                b.Timestamp = t
            }
        }
        if expires.Valid {
            if exp, err := time.Parse(time.RFC3339, expires.String); err == nil {
                b.ExpiresAt = &exp
            }
        }
        if rule.Valid {
            b.Rule = rule.String
        }
        if reason.Valid {
            b.Reason = reason.String
        }
        
        // Corrected ASN parsing and assignment
        if asn.Valid {
            asnStr := strings.TrimPrefix(asn.String, "AS")
            if val, err := strconv.ParseUint(asnStr, 10, 32); err == nil {
                b.ASN = uint32(val)
            } else {
                log.Printf("[ERROR] Failed to parse ASN: %v", err)
            }
        }

        if asnName.Valid {
            b.ASNName = asnName.String
        }
        if country.Valid {
            b.Country = country.String
        }
        if ptr.Valid {
            b.PTR = ptr.String
        }

        result[b.Prefix] = b
    }

    if err := rows.Err(); err != nil {
        log.Printf("[ERROR] Rows error: %v", err)
        http.Error(w, "Failed to read blackholes", http.StatusInternalServerError)
        return
    }

    _ = json.NewEncoder(w).Encode(result)
}







// handleFlush clears the database and BGP announcements for a fresh start.
func handleFlush(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if DB == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	// 1. Get all currently announced prefixes from the BGP server
	allAnnouncements := bgp.ListAnnouncements()
	var announcedPrefixes []string
	for prefix := range allAnnouncements {
		announcedPrefixes = append(announcedPrefixes, prefix)
	}

	announcedCount := len(announcedPrefixes)

	// 2. Withdraw each announced prefix using your existing bgp.WithdrawPrefix logic
	for _, prefix := range announcedPrefixes {
		if err := bgp.WithdrawPrefix(prefix); err != nil {
			log.Printf("[WARN] Failed to withdraw BGP prefix %s: %v", prefix, err)
		}
	}
	log.Printf("[INFO] Withdrawn all %d prefixes from BGP.", announcedCount)

	// 3. Clear the database tables and capture the number of rows affected
	detectionsResult, err := DB.Exec(`DELETE FROM detections`)
	if err != nil {
		log.Printf("[ERROR] DB error deleting detections: %v", err)
		http.Error(w, "Failed to flush detections", http.StatusInternalServerError)
		return
	}
	detectionsCount, _ := detectionsResult.RowsAffected()

	blackholesResult, err := DB.Exec(`DELETE FROM blackholes`)
	if err != nil {
		log.Printf("[ERROR] DB error deleting blackholes: %v", err)
		http.Error(w, "Failed to flush blackholes", http.StatusInternalServerError)
		return
	}
	blackholesCount, _ := blackholesResult.RowsAffected()

	// 4. Respond with a detailed success message
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"message": "All data flushed successfully.",
		"rib_announcements_cleared": announcedCount,
		"db_blackholes_cleared": blackholesCount,
		"db_detections_cleared": detectionsCount,
	})
}
