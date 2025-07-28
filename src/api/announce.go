package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"flowenricher/bgp"
)

type AnnouncedPrefix struct {
	Prefix      string   `json:"prefix"`
	NextHop     string   `json:"next_hop"`
	Communities []string `json:"communities"`
	Timestamp   time.Time `json:"timestamp"`
}

var activeAnnouncements = make(map[string]AnnouncedPrefix)

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

	attrs := []string{}
	if len(req.Communities) > 0 {
		attrs = append(attrs, fmt.Sprintf("community %s", strings.Join(req.Communities, ",")))
	}

	err := bgp.AnnouncePrefix(req.Prefix, req.NextHop, req.Communities)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to announce: %v", err), http.StatusInternalServerError)
		return
	}

	req.Timestamp = time.Now()
	activeAnnouncements[req.Prefix] = req

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

	delete(activeAnnouncements, req.Prefix)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Withdrawn %s\n", req.Prefix)
}

func handleListAnnouncements(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activeAnnouncements)
}
