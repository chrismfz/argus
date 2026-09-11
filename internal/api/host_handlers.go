package api

import (
	"net/http"
	"strconv"
	"time"

	"argus/internal/flowstore"
)

// Per-local-host ("My Hosts") traffic API — the follow-up to a bandwidth spike
// on an interface graph. Backed by the 30-min detail rollups keyed on local_ip
// (see flowstore.QueryLocalHostInsights). IP-only, like the other /debug/*
// endpoints.
//
//	GET /debug/host?ip=84.54.49.202&hours=24&top=15
//	    → that host's in/out series + top remote peers/ASNs/ports/countries
//	GET /debug/hosts?hours=24&top=25
//	    → our busiest local hosts by bytes over the window

// hostWindow parses the shared ?hours= (default 24, clamped 1..168) into a
// [since, until) unix-second window ending now.
func hostWindow(r *http.Request) (since, until int64) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hours = n
		}
	}
	if hours < 1 {
		hours = 1
	}
	if hours > 168 { // 7 days = the detail-table retention
		hours = 168
	}
	until = time.Now().Unix()
	since = until - int64(hours)*3600
	return since, until
}

func hostTopN(r *http.Request, def int) int {
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func handleHostInsights(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "flow DB unavailable"})
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provide ?ip=<local address> (one of your my_prefixes hosts)"})
		return
	}
	since, until := hostWindow(r)
	ins, err := flowstore.QueryLocalHostInsights(DB, ip, since, until, hostTopN(r, 15))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ins)
}

func handleTopHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "flow DB unavailable"})
		return
	}
	since, until := hostWindow(r)
	hosts, err := flowstore.QueryTopLocalHosts(DB, since, until, hostTopN(r, 25))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"since": since,
		"until": until,
		"count": len(hosts),
		"hosts": hosts,
		// Derived from the per-ASN top-N detail — dominant hosts, not exact totals.
		"partial": true,
	})
}
