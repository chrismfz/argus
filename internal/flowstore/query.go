package flowstore

import (
	"database/sql"
	"time"
)

// ── Public result types ───────────────────────────────────────────────────────

// TimelinePoint is one 5-min bucket of in/out traffic for an ASN.
type TimelinePoint struct {
	Ts      int64  `json:"ts"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// IfaceSplit shows how many bytes of an ASN's traffic traversed each upstream
// interface in a given 5-min window.
type IfaceSplit struct {
	Ts    int64  `json:"ts"`
	Dir   string `json:"dir"`
	Iface string `json:"iface"`
	Bytes uint64 `json:"bytes"`
}

// IPPair is one row from flowstore_top_ips.
type IPPair struct {
	PeerIP  string `json:"peer_ip"`
	LocalIP string `json:"local_ip"`
	Proto   uint8  `json:"proto"`
	DstPort uint16 `json:"dst_port"`
	Country string `json:"country"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// PrefixStat is one row from flowstore_top_prefixes.
type PrefixStat struct {
	Prefix  string `json:"prefix"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// ProtoStat is one row from flowstore_proto.
type ProtoStat struct {
	Proto   uint8  `json:"proto"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// CountryStat is one row from flowstore_country.
type CountryStat struct {
	Country string `json:"country"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// PortStat is one row from flowstore_ports.
type PortStat struct {
	DstPort uint16 `json:"dst_port"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// TCPFlagsStat aggregates TCP flag counters across all hours in the window.
type TCPFlagsStat struct {
	TCPFlows uint64 `json:"tcp_flows"`
	SYN      uint64 `json:"syn"`
	ACK      uint64 `json:"ack"`
	RST      uint64 `json:"rst"`
	FIN      uint64 `json:"fin"`
	PSH      uint64 `json:"psh"`
	URG      uint64 `json:"urg"`
}

// ASNMeta is a row from flowstore_asn_meta.
type ASNMeta struct {
	ASN       uint32 `json:"asn"`
	ASNName   string `json:"asn_name"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	TotalIn   uint64 `json:"total_in"`
	TotalOut  uint64 `json:"total_out"`
}

// KnownASN is a lightweight entry for listing all known ASNs.
type KnownASN struct {
	ASN     uint32 `json:"asn"`
	ASNName string `json:"asn_name"`
}

// ── Helper ────────────────────────────────────────────────────────────────────

func cutoffFor(window time.Duration) int64 {
	return time.Now().Add(-window).Unix()
}

// hourCutoff returns the hour-aligned cutoff — we include any hourly bucket
// whose ts >= cutoff so that the very first hour bucket is included in full.
func hourCutoff(window time.Duration) int64 {
	raw := cutoffFor(window)
	return (raw / 3600) * 3600
}

// ── Timeline ──────────────────────────────────────────────────────────────────

// QueryTimeline returns 5-min timeline points for asn over the given window.
func QueryTimeline(db *sql.DB, asn uint32, window time.Duration) ([]TimelinePoint, error) {
	cutoff := cutoffFor(window)
	rows, err := db.Query(`
		SELECT ts, dir, bytes, packets, flows
		FROM flowstore_timeline
		WHERE asn = ? AND ts >= ?
		ORDER BY ts ASC
	`, asn, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelinePoint
	for rows.Next() {
		var p TimelinePoint
		if err := rows.Scan(&p.Ts, &p.Dir, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// QueryIfaceSplit returns per-interface byte splits for asn over the window.
func QueryIfaceSplit(db *sql.DB, asn uint32, window time.Duration) ([]IfaceSplit, error) {
	cutoff := cutoffFor(window)
	rows, err := db.Query(`
		SELECT ts, dir, iface, bytes
		FROM flowstore_timeline_iface
		WHERE asn = ? AND ts >= ?
		ORDER BY ts ASC
	`, asn, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IfaceSplit
	for rows.Next() {
		var s IfaceSplit
		if err := rows.Scan(&s.Ts, &s.Dir, &s.Iface, &s.Bytes); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── Top IPs ───────────────────────────────────────────────────────────────────

// QueryTopIPs returns the top IP pairs for asn over the window, sorted by bytes.
// If dir is "in", "out", or "both", results are filtered or merged accordingly.
func QueryTopIPs(db *sql.DB, asn uint32, window time.Duration, dir string) ([]IPPair, error) {
	cutoff := hourCutoff(window)

	var rows *sql.Rows
	var err error

	if dir == "in" || dir == "out" {
		rows, err = db.Query(`
			SELECT peer_ip, local_ip, proto, dst_port, country, dir,
			       SUM(bytes) AS bytes, SUM(packets) AS packets, SUM(flows) AS flows
			FROM flowstore_top_ips
			WHERE asn = ? AND ts >= ? AND dir = ?
			GROUP BY peer_ip, local_ip, proto, dst_port, country, dir
			ORDER BY bytes DESC
			LIMIT ?
		`, asn, cutoff, dir, topIPs)
	} else {
		rows, err = db.Query(`
			SELECT peer_ip, local_ip, proto, dst_port, country, dir,
			       SUM(bytes) AS bytes, SUM(packets) AS packets, SUM(flows) AS flows
			FROM flowstore_top_ips
			WHERE asn = ? AND ts >= ?
			GROUP BY peer_ip, local_ip, proto, dst_port, country, dir
			ORDER BY bytes DESC
			LIMIT ?
		`, asn, cutoff, topIPs)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPPair
	for rows.Next() {
		var p IPPair
		if err := rows.Scan(
			&p.PeerIP, &p.LocalIP, &p.Proto, &p.DstPort, &p.Country, &p.Dir,
			&p.Bytes, &p.Packets, &p.Flows,
		); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── Top Prefixes ──────────────────────────────────────────────────────────────

// QueryTopPrefixes returns the top BGP prefixes for asn over the window.
func QueryTopPrefixes(db *sql.DB, asn uint32, window time.Duration) ([]PrefixStat, error) {
	cutoff := hourCutoff(window)
	rows, err := db.Query(`
		SELECT prefix, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_top_prefixes
		WHERE asn = ? AND ts >= ?
		GROUP BY prefix, dir
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, asn, cutoff, topPfx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrefixStat
	for rows.Next() {
		var p PrefixStat
		if err := rows.Scan(&p.Prefix, &p.Dir, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── Protocol breakdown ────────────────────────────────────────────────────────

// QueryProto returns the protocol breakdown for asn over the window.
func QueryProto(db *sql.DB, asn uint32, window time.Duration) ([]ProtoStat, error) {
	cutoff := hourCutoff(window)
	rows, err := db.Query(`
		SELECT proto, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_proto
		WHERE asn = ? AND ts >= ?
		GROUP BY proto, dir
		ORDER BY SUM(bytes) DESC
	`, asn, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProtoStat
	for rows.Next() {
		var p ProtoStat
		if err := rows.Scan(&p.Proto, &p.Dir, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── Country breakdown ─────────────────────────────────────────────────────────

// QueryCountry returns the country breakdown for asn over the window.
func QueryCountry(db *sql.DB, asn uint32, window time.Duration) ([]CountryStat, error) {
	cutoff := hourCutoff(window)
	rows, err := db.Query(`
		SELECT country, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_country
		WHERE asn = ? AND ts >= ?
		GROUP BY country, dir
		ORDER BY SUM(bytes) DESC
	`, asn, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountryStat
	for rows.Next() {
		var s CountryStat
		if err := rows.Scan(&s.Country, &s.Dir, &s.Bytes, &s.Packets, &s.Flows); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── Ports ─────────────────────────────────────────────────────────────────────

// QueryPorts returns the top destination ports for asn over the window.
func QueryPorts(db *sql.DB, asn uint32, window time.Duration) ([]PortStat, error) {
	cutoff := hourCutoff(window)
	rows, err := db.Query(`
		SELECT dst_port, dir, SUM(bytes), SUM(packets), SUM(flows)
		FROM flowstore_ports
		WHERE asn = ? AND ts >= ?
		GROUP BY dst_port, dir
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, asn, cutoff, topPorts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortStat
	for rows.Next() {
		var p PortStat
		if err := rows.Scan(&p.DstPort, &p.Dir, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── TCP Flags ─────────────────────────────────────────────────────────────────

// QueryTCPFlags returns aggregated TCP flag counters for asn over the window.
func QueryTCPFlags(db *sql.DB, asn uint32, window time.Duration) (*TCPFlagsStat, error) {
	cutoff := hourCutoff(window)
	row := db.QueryRow(`
		SELECT
			SUM(tcp_flows), SUM(syn_count), SUM(ack_count),
			SUM(rst_count), SUM(fin_count), SUM(psh_count), SUM(urg_count)
		FROM flowstore_tcp_flags
		WHERE asn = ? AND ts >= ?
	`, asn, cutoff)
	var f TCPFlagsStat
	var (
		tcpFlows, syn, ack, rst, fin, psh, urg sql.NullInt64
	)
	if err := row.Scan(&tcpFlows, &syn, &ack, &rst, &fin, &psh, &urg); err != nil {
		return &f, nil // no rows is fine, return zero struct
	}
	f.TCPFlows = uint64(tcpFlows.Int64)
	f.SYN = uint64(syn.Int64)
	f.ACK = uint64(ack.Int64)
	f.RST = uint64(rst.Int64)
	f.FIN = uint64(fin.Int64)
	f.PSH = uint64(psh.Int64)
	f.URG = uint64(urg.Int64)
	return &f, nil
}

// ── ASN Meta ──────────────────────────────────────────────────────────────────

// QueryMeta returns the permanent metadata record for asn.
func QueryMeta(db *sql.DB, asn uint32) (*ASNMeta, error) {
	row := db.QueryRow(`
		SELECT asn, asn_name, first_seen, last_seen, total_in, total_out
		FROM flowstore_asn_meta WHERE asn = ?
	`, asn)
	var m ASNMeta
	if err := row.Scan(
		&m.ASN, &m.ASNName, &m.FirstSeen, &m.LastSeen, &m.TotalIn, &m.TotalOut,
	); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListKnownASNs returns all ASNs in flowstore_asn_meta, most-recently-seen first.
func ListKnownASNs(db *sql.DB) ([]KnownASN, error) {
	rows, err := db.Query(`
		SELECT asn, asn_name FROM flowstore_asn_meta ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KnownASN
	for rows.Next() {
		var k KnownASN
		if err := rows.Scan(&k.ASN, &k.ASNName); err != nil {
			continue
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
