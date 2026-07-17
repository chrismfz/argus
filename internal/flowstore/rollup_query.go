package flowstore

import (
	"database/sql"
	"time"
)

// ── Tier-2 daily rollup queries ───────────────────────────────────────────────
// Read helpers over the flowstore_daily_* tables. These back the long-range
// history views (Phase 3 UI); kept here so the rollup schema and its readers
// live together.

// DailyIPTotal is one per-IP per-day total (in/out split folded into Dir).
type DailyIPTotal struct {
	Day     int64  `json:"day"`
	Dir     string `json:"dir"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// QueryIPDailyHistory returns an IP's daily in/out totals, newest day first,
// from the per-IP rollup — so even an IP that never topped an ASN bucket has a
// history. maxDays <= 0 defaults to 365.
func QueryIPDailyHistory(db *sql.DB, ip string, maxDays int) ([]DailyIPTotal, error) {
	if maxDays <= 0 {
		maxDays = 365
	}
	rows, err := db.Query(`
		SELECT day, dir, bytes, packets, flows
		FROM flowstore_daily_ip_totals
		WHERE peer_ip = ?
		ORDER BY day DESC
		LIMIT ?`, ip, maxDays*2) // *2: up to one in + one out row per day
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyIPTotal
	for rows.Next() {
		var d DailyIPTotal
		if err := rows.Scan(&d.Day, &d.Dir, &d.Bytes, &d.Packets, &d.Flows); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DailyIPRow is one row from flowstore_daily_ips.
type DailyIPRow struct {
	Day     int64  `json:"day"`
	Dir     string `json:"dir"`
	PeerIP  string `json:"peer_ip"`
	LocalIP string `json:"local_ip"`
	Proto   uint8  `json:"proto"`
	DstPort uint16 `json:"dst_port"`
	Country string `json:"country"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// QueryASNDailyTopIPs returns the daily top-IP rollup rows for an ASN over the
// last maxDays (default 30), newest day first.
func QueryASNDailyTopIPs(db *sql.DB, asn uint32, maxDays int) ([]DailyIPRow, error) {
	if maxDays <= 0 {
		maxDays = 30
	}
	cutoff := dayStart(time.Now().UTC().Unix()) - int64(maxDays)*daySeconds
	rows, err := db.Query(`
		SELECT day, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows
		FROM flowstore_daily_ips
		WHERE asn = ? AND day >= ?
		ORDER BY day DESC, bytes DESC`, asn, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyIPRow
	for rows.Next() {
		var r DailyIPRow
		if err := rows.Scan(&r.Day, &r.Dir, &r.PeerIP, &r.LocalIP, &r.Proto, &r.DstPort,
			&r.Country, &r.Bytes, &r.Packets, &r.Flows); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
