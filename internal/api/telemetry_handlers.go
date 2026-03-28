package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"argus/internal/telemetry"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func telJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func telReady(w http.ResponseWriter) bool {
	if telemetry.Global == nil {
		http.Error(w, `{"error":"telemetry not yet initialised"}`, http.StatusServiceUnavailable)
		return false
	}
	return true
}

func queryInt(r *http.Request, key string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || v < min || v > max {
		return def
	}
	return v
}

// ── /tel/timeseries ───────────────────────────────────────────────────────────

func handleTelTimeSeries(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	minutes := queryInt(r, "minutes", 1440, 1, 1440)
	telJSON(w, telemetry.Global.QueryTimeSeries(minutes))
}

// ── /tel/asn ─────────────────────────────────────────────────────────────────

func handleTelASN(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	n := queryInt(r, "n", 20, 1, 200)
	minutes := queryInt(r, "minutes", 1440, 1, 1440)
	topIn, topOut := telemetry.Global.QueryTopASN(n, minutes)
	telJSON(w, map[string]any{
		"top_in":  topIn,
		"top_out": topOut,
	})
}

// ── /tel/sankey ───────────────────────────────────────────────────────────────

func handleTelSankey(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	limit := queryInt(r, "limit", 30, 1, 200)
	sankeyIn, sankeyOut := telemetry.Global.QuerySankey(limit)
	telJSON(w, map[string]any{
		"incoming": sankeyIn,
		"outgoing": sankeyOut,
	})
}

// ── /tel/hosts ────────────────────────────────────────────────────────────────

func handleTelHosts(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	n := queryInt(r, "n", 20, 1, 200)
	hostsIn, hostsOut := telemetry.Global.QueryTopHosts(n)
	telJSON(w, map[string]any{
		"hosts_in":  hostsIn,
		"hosts_out": hostsOut,
	})
}

// ── /tel/ports ────────────────────────────────────────────────────────────────

func handleTelPorts(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	n := queryInt(r, "n", 50, 1, 200)
	telJSON(w, telemetry.Global.QueryPorts(n))
}

// ── /tel/overview ─────────────────────────────────────────────────────────────

func handleTelOverview(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	minutes := queryInt(r, "minutes", 60, 1, 1440)

	topIn, topOut := telemetry.Global.QueryTopASN(10, 1440)
	sankeyIn, sankeyOut := telemetry.Global.QuerySankey(25)
	hostsIn, hostsOut := telemetry.Global.QueryTopHosts(10)
	ports := telemetry.Global.QueryPorts(30)
	ts := telemetry.Global.QueryTimeSeries(minutes)

	var totalIn, totalOut, flowsIn, flowsOut uint64
	for _, b := range ts {
		totalIn += b.BytesIn
		totalOut += b.BytesOut
		flowsIn += b.FlowsIn
		flowsOut += b.FlowsOut
	}

	telJSON(w, map[string]any{
		"ts":         time.Now().Unix(),
		"total_in":   totalIn,
		"total_out":  totalOut,
		"flows_in":   flowsIn,
		"flows_out":  flowsOut,
		"timeseries": ts,
		"asn_in":     topIn,
		"asn_out":    topOut,
		"sankey_in":  sankeyIn,
		"sankey_out": sankeyOut,
		"hosts_in":   hostsIn,
		"hosts_out":  hostsOut,
		"ports":      ports,
	})
}

// ── /tel/snapshots ────────────────────────────────────────────────────────────

func handleTelSnapshots(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		if TelemetryDB == nil {
			http.Error(w, `{"error":"db not ready"}`, http.StatusServiceUnavailable)
			return
		}
		list, err := telemetry.ListSnapshots(TelemetryDB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		telJSON(w, list)

	case http.MethodPost:
		if TelemetryDB == nil || !telReady(w) {
			return
		}
		var req struct {
			Note string `json:"note"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		id, err := telemetry.TakeManualSnapshot(TelemetryDB, req.Note)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		telJSON(w, map[string]any{"id": id, "note": req.Note, "ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── /tel/snapshot ─────────────────────────────────────────────────────────────

func handleTelSnapshotGet(w http.ResponseWriter, r *http.Request) {
	if TelemetryDB == nil {
		http.Error(w, `{"error":"db not ready"}`, http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
		return
	}
	data, meta, err := telemetry.GetSnapshot(TelemetryDB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	telJSON(w, map[string]any{"meta": meta, "data": data})
}

// ── /tel/history ──────────────────────────────────────────────────────────────

func handleTelHistory(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	if TelemetryDB == nil {
		http.Error(w, `{"error":"db not ready"}`, http.StatusServiceUnavailable)
		return
	}

	asn64, err := strconv.ParseUint(r.URL.Query().Get("asn"), 10, 32)
	if err != nil || asn64 == 0 {
		http.Error(w, `{"error":"invalid asn"}`, http.StatusBadRequest)
		return
	}
	asn := uint32(asn64)

	hist, err := telemetry.GetASNHistory(TelemetryDB, asn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	topIn, topOut := telemetry.Global.QueryTopASN(500, 1440)
	var liveIn, liveOut, liveFlowsIn, liveFlowsOut uint64
	var asnName string
	for _, s := range topIn {
		if s.ASN == asn {
			liveIn, liveFlowsIn, asnName = s.BytesIn, s.FlowsIn, s.Name
			break
		}
	}
	for _, s := range topOut {
		if s.ASN == asn {
			liveOut, liveFlowsOut = s.BytesOut, s.FlowsOut
			if asnName == "" {
				asnName = s.Name
			}
			break
		}
	}

	telJSON(w, map[string]any{
		"asn":      asn,
		"asn_name": asnName,
		"live": map[string]any{
			"period":    "live",
			"label":     "last 24h (live)",
			"ts_start":  time.Now().Add(-24 * time.Hour).Unix(),
			"bytes_in":  liveIn,
			"bytes_out": liveOut,
			"flows_in":  liveFlowsIn,
			"flows_out": liveFlowsOut,
		},
		"history": hist,
	})
}



func handleTelInterfaces(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	minutes := queryInt(r, "minutes", 1440, 1, 1440)
	telJSON(w, telemetry.Global.QueryInterfaces(minutes))
}


func handleTelIfaceSankey(w http.ResponseWriter, r *http.Request) {
	if !telReady(w) {
		return
	}
	limit := queryInt(r, "limit", 30, 1, 200)
	sankeyIn, sankeyOut := telemetry.Global.QueryIfaceASNSankey(limit)
	telJSON(w, map[string]any{
		"incoming": sankeyIn,
		"outgoing": sankeyOut,
	})
}
