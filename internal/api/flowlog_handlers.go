package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"argus/internal/flowlog"
)

// handleFlowLog serves the Phase 2 Tier-0 raw flow log as JSON.
//
//	GET /debug/flowlog                         → stats only (row count + size)
//	GET /debug/flowlog?ip=1.2.3.4&limit=200    → recent flows touching that IP
//	    optional: src_ip, dst_ip, proto, port, dir=in|out, since, until (unix s)
//
// IP-only (no token), consistent with the other /debug/* endpoints.
func handleFlowLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	lg := flowlog.Global
	if lg == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"hint":    "set flowlog.enabled: true in config.yaml to capture raw flows",
		})
		return
	}

	q := r.URL.Query()
	f := flowlog.Filter{
		IP:    q.Get("ip"),
		SrcIP: q.Get("src_ip"),
		DstIP: q.Get("dst_ip"),
		Dir:   q.Get("dir"),
	}
	if v := q.Get("proto"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 8); err == nil {
			f.Proto, f.HasProto = uint8(n), true
		}
	}
	if v := q.Get("port"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			f.Port, f.HasPort = uint16(n), true
		}
	}
	if v := q.Get("since"); v != "" {
		f.Since, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("until"); v != "" {
		f.Until, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}

	rowCount, sizeBytes, err := lg.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{
		"enabled":   true,
		"row_count": rowCount,
		"size_mb":   float64(sizeBytes) / (1 << 20),
	}

	// No filter → stats only (avoid dumping the newest 1000 rows unasked).
	if f.IP == "" && f.SrcIP == "" && f.DstIP == "" && !f.HasProto && !f.HasPort &&
		f.Dir == "" && f.Since == 0 && f.Until == 0 {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	flows, err := lg.Query(f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	resp["count"] = len(flows)
	resp["flows"] = flows
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
