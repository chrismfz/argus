package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"net"
	"flowenricher/bgp"
	"flowenricher/config"
)

type AnnouncedPrefix struct {
	Prefix      string   `json:"prefix"`
	NextHop     string   `json:"next_hop"`
	Communities []string `json:"communities"`
	Timestamp   time.Time `json:"timestamp"`
	ASPath []uint32 `json:"as_path,omitempty"`
	IsBlackhole bool `json:"blackhole"`
}

// ❌ Δεν χρειάζεται πια
// var activeAnnouncements = make(map[string]AnnouncedPrefix)

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


req.ASPath = []uint32{config.GetMyASN()} // ✅




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
