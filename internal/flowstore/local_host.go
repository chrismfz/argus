package flowstore

import (
	"database/sql"
	"fmt"
)

// Per-local-host ("My Hosts") traffic views — the follow-up to a bandwidth
// spike on an interface graph: "how much is ONE of MY hosts sending/receiving,
// to whom, on what port". These read the 30-minute detail table
// flowstore_top_ips (ts-based, ~7-day detail retention, includes the current
// day), filtered by local_ip.
//
// COMPLETENESS CAVEAT: flowstore_top_ips holds the per-30-min top-N IP rows per
// (asn, dir). So a host's traffic that is spread across many small,
// below-top-N peers can be undercounted — these views are "who/what dominates
// this host", not billing-grade totals. Every result therefore carries
// Partial=true. An exact per-local-host rollup is future work (see
// docs/ip-insights-and-traffic-anomaly-mcp.md). Direction is network-relative:
// dir="out" is traffic leaving our AS (a server's egress to clients — the POP3
// drain shape), dir="in" is traffic arriving into our AS.

// LocalHostPoint is one 30-minute bucket of a local host's in/out bytes.
type LocalHostPoint struct {
	TS       int64  `json:"ts"`
	InBytes  uint64 `json:"in_bytes"`
	OutBytes uint64 `json:"out_bytes"`
}

// LocalHostRank is one ranked counterpart of a local host's traffic (a remote
// peer IP, an ASN, a destination port, or a country), split by direction.
type LocalHostRank struct {
	Key      string `json:"key"`
	InBytes  uint64 `json:"in_bytes"`
	OutBytes uint64 `json:"out_bytes"`
	Bytes    uint64 `json:"bytes"` // in+out; the sort key
}

// LocalHostInsights is the full per-host answer over [Since, Until).
type LocalHostInsights struct {
	IP           string           `json:"ip"`
	Since        int64            `json:"since"`
	Until        int64            `json:"until"`
	InBytes      uint64           `json:"in_bytes"`
	OutBytes     uint64           `json:"out_bytes"`
	Series       []LocalHostPoint `json:"series"`
	TopPeers     []LocalHostRank  `json:"top_peers"`
	TopASNs      []LocalHostRank  `json:"top_asns"`
	TopPorts     []LocalHostRank  `json:"top_ports"`
	TopCountries []LocalHostRank  `json:"top_countries"`
	// Partial is always true: these views are derived from the per-ASN top-N
	// detail, so below-top-N tail may be undercounted (see the file header).
	Partial bool `json:"partial"`
}

// LocalTalker is one of our busiest local hosts by bytes over a window.
type LocalTalker struct {
	LocalIP  string `json:"local_ip"`
	InBytes  uint64 `json:"in_bytes"`
	OutBytes uint64 `json:"out_bytes"`
	Bytes    uint64 `json:"bytes"` // in+out; the sort key
}

// clampLocalTop bounds a caller-supplied top-N to a sane range.
func clampLocalTop(top int) int {
	if top <= 0 {
		return 15
	}
	if top > 200 {
		return 200
	}
	return top
}

// QueryLocalHostInsights returns the traffic profile of one local host over
// [since, until): a 30-min in/out series plus the top remote peers / ASNs /
// ports / countries. topN bounds each ranked list.
func QueryLocalHostInsights(db *sql.DB, ip string, since, until int64, topN int) (*LocalHostInsights, error) {
	topN = clampLocalTop(topN)
	out := &LocalHostInsights{
		IP:      ip,
		Since:   since,
		Until:   until,
		Series:  []LocalHostPoint{},
		Partial: true,
	}

	series, in, egress, err := queryLocalSeries(db, ip, since, until)
	if err != nil {
		return nil, err
	}
	out.Series, out.InBytes, out.OutBytes = series, in, egress

	for _, spec := range []struct {
		dst  *[]LocalHostRank
		expr string
	}{
		{&out.TopPeers, "peer_ip"},
		{&out.TopASNs, "CAST(asn AS TEXT)"},
		{&out.TopPorts, "CAST(dst_port AS TEXT)"},
		{&out.TopCountries, "country"},
	} {
		rank, err := queryLocalRank(db, ip, since, until, spec.expr, topN)
		if err != nil {
			return nil, err
		}
		*spec.dst = rank
	}
	return out, nil
}

// queryLocalSeries returns the per-30-min in/out byte series for one local host
// plus the window totals (sum of the series).
func queryLocalSeries(db *sql.DB, ip string, since, until int64) ([]LocalHostPoint, uint64, uint64, error) {
	rows, err := db.Query(`
		SELECT ts,
		       COALESCE(SUM(CASE WHEN dir='in'  THEN bytes ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN dir='out' THEN bytes ELSE 0 END), 0)
		FROM flowstore_top_ips
		WHERE local_ip = ? AND ts >= ? AND ts < ?
		GROUP BY ts
		ORDER BY ts ASC`, ip, since, until)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	series := []LocalHostPoint{}
	var totalIn, totalOut uint64
	for rows.Next() {
		var p LocalHostPoint
		if err := rows.Scan(&p.TS, &p.InBytes, &p.OutBytes); err != nil {
			return nil, 0, 0, err
		}
		totalIn += p.InBytes
		totalOut += p.OutBytes
		series = append(series, p)
	}
	return series, totalIn, totalOut, rows.Err()
}

// queryLocalRank ranks one counterpart dimension (keyExpr) of a local host's
// traffic by total bytes, split by direction. keyExpr must be a trusted column
// expression (never user input) — callers pass fixed literals.
func queryLocalRank(db *sql.DB, ip string, since, until int64, keyExpr string, limit int) ([]LocalHostRank, error) {
	q := fmt.Sprintf(`
		SELECT %s AS k,
		       COALESCE(SUM(CASE WHEN dir='in'  THEN bytes ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN dir='out' THEN bytes ELSE 0 END), 0)
		FROM flowstore_top_ips
		WHERE local_ip = ? AND ts >= ? AND ts < ?
		GROUP BY k
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, keyExpr)
	rows, err := db.Query(q, ip, since, until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LocalHostRank{}
	for rows.Next() {
		var r LocalHostRank
		if err := rows.Scan(&r.Key, &r.InBytes, &r.OutBytes); err != nil {
			return nil, err
		}
		r.Bytes = r.InBytes + r.OutBytes
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryTopLocalHosts returns our busiest local hosts by total bytes over
// [since, until), so "which of my servers is hot" is one query.
func QueryTopLocalHosts(db *sql.DB, since, until int64, topN int) ([]LocalTalker, error) {
	topN = clampLocalTop(topN)
	rows, err := db.Query(`
		SELECT local_ip,
		       COALESCE(SUM(CASE WHEN dir='in'  THEN bytes ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN dir='out' THEN bytes ELSE 0 END), 0)
		FROM flowstore_top_ips
		WHERE ts >= ? AND ts < ?
		GROUP BY local_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, since, until, topN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LocalTalker{}
	for rows.Next() {
		var t LocalTalker
		if err := rows.Scan(&t.LocalIP, &t.InBytes, &t.OutBytes); err != nil {
			return nil, err
		}
		t.Bytes = t.InBytes + t.OutBytes
		out = append(out, t)
	}
	return out, rows.Err()
}
