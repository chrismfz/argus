package api

import (
	"net/http"
	"strconv"

	"argus/internal/flowstore"
)

// handleDailyRollup exposes the Tier-2 daily rollups for verification / the
// Phase-3 UI.
//
//	GET /debug/rollup?ip=1.2.3.4        → that IP's per-day in/out totals
//	GET /debug/rollup?asn=15169&days=14 → an ASN's daily top-IP rollup
//
// IP-only (no token), like the other /debug/* endpoints.
func handleDailyRollup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "flow DB unavailable"})
		return
	}
	q := r.URL.Query()
	days := 0
	if v := q.Get("days"); v != "" {
		days, _ = strconv.Atoi(v)
	}

	if ip := q.Get("ip"); ip != "" {
		hist, err := flowstore.QueryIPDailyHistory(DB, ip, days)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "count": len(hist), "days": hist})
		return
	}
	if v := q.Get("asn"); v != "" {
		asn, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad asn"})
			return
		}
		top, err := flowstore.QueryASNDailyTopIPs(DB, uint32(asn), days)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"asn": asn, "count": len(top), "rows": top})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error": "provide ?ip=<addr> or ?asn=<number>",
	})
}
