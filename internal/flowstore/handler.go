package flowstore

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// ── Window parsing ────────────────────────────────────────────────────────────

var validWindows = map[string]time.Duration{
	"1h":  1 * time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"48h": 48 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

func parseWindow(r *http.Request) time.Duration {
	w := r.URL.Query().Get("window")
	if d, ok := validWindows[w]; ok {
		return d
	}
	return 24 * time.Hour // default
}

func parseASN(r *http.Request) (uint32, bool) {
	// Expects the last path segment to be the ASN number.
	// e.g. /api/asn/12345 → "12345"
	seg := r.PathValue("asn")
	if seg == "" {
		// Fallback: ?asn= query param
		seg = r.URL.Query().Get("asn")
	}
	v, err := strconv.ParseUint(seg, 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ── Response envelope ─────────────────────────────────────────────────────────

// ASNSummaryResponse is returned by GET /api/asn/{asn}.
type ASNSummaryResponse struct {
	Meta *ASNMeta `json:"meta"` // nil if ASN not yet seen
}

// ASNTimelineResponse is returned by GET /api/asn/{asn}/timeline.
type ASNTimelineResponse struct {
	Window  string          `json:"window"`
	Points  []TimelinePoint `json:"points"`
	Ifaces  []IfaceSplit    `json:"ifaces"`
}

// ASNDetailResponse is returned by GET /api/asn/{asn}/detail.
type ASNDetailResponse struct {
	Window    string        `json:"window"`
	TopIPs    []IPPair      `json:"top_ips"`
	Prefixes  []PrefixStat  `json:"prefixes"`
	Proto     []ProtoStat   `json:"proto"`
	Countries []CountryStat `json:"countries"`
	Ports     []PortStat    `json:"ports"`
	TCPFlags  *TCPFlagsStat `json:"tcp_flags"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// HandleASNSummary serves GET /api/asn/{asn}
// Returns permanent metadata for the ASN (first seen, last seen, lifetime bytes).
func HandleASNSummary(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asn, ok := parseASN(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid or missing ASN")
			return
		}
		meta, err := QueryMeta(db, asn)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, ASNSummaryResponse{Meta: meta})
	}
}

// HandleASNTimeline serves GET /api/asn/{asn}/timeline?window=24h
// Returns 5-min traffic timeline + interface split for the requested window.
func HandleASNTimeline(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asn, ok := parseASN(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid or missing ASN")
			return
		}
		windowStr := r.URL.Query().Get("window")
		window    := parseWindow(r)

		points, err := QueryTimeline(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ifaces, err := QueryIfaceSplit(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if windowStr == "" {
			windowStr = "24h"
		}
		writeJSON(w, ASNTimelineResponse{
			Window: windowStr,
			Points: points,
			Ifaces: ifaces,
		})
	}
}

// HandleASNDetail serves GET /api/asn/{asn}/detail?window=24h&dir=both
// Returns all hourly aggregates: top IPs, prefixes, proto, country, ports, TCP flags.
func HandleASNDetail(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asn, ok := parseASN(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid or missing ASN")
			return
		}
		windowStr := r.URL.Query().Get("window")
		window    := parseWindow(r)
		dir       := r.URL.Query().Get("dir") // "in" | "out" | "both" (default)
		if dir == "" {
			dir = "both"
		}

		ips, err := QueryTopIPs(db, asn, window, dir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		pfx, err := QueryTopPrefixes(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		proto, err := QueryProto(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		countries, err := QueryCountry(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ports, err := QueryPorts(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		flags, err := QueryTCPFlags(db, asn, window)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if windowStr == "" {
			windowStr = "24h"
		}
		writeJSON(w, ASNDetailResponse{
			Window:    windowStr,
			TopIPs:    ips,
			Prefixes:  pfx,
			Proto:     proto,
			Countries: countries,
			Ports:     ports,
			TCPFlags:  flags,
		})
	}
}
