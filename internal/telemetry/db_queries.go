package telemetry

import (
	"database/sql"
	"sort"
	"time"
)

// MaxRingMinutes is the in-memory ring capacity. Requests beyond this fall
// through to the SQLite-backed query functions.
const MaxRingMinutes = RingSize // 1440

// ── Transparent wrappers ─────────────────────────────────────────────────────
// These are the functions handlers should call. They automatically route to
// the ring when minutes <= 1440, and to SQLite otherwise.

// QueryTimeSeriesAny returns minute buckets for the requested window.
func QueryTimeSeriesAny(db *sql.DB, minutes int) []MinuteBucket {
	if minutes <= MaxRingMinutes && Global != nil {
		return Global.QueryTimeSeries(minutes)
	}
	result, _ := QueryTimeSeriesFromDB(db, minutes)
	return result
}

// QueryTopASNAny returns top N ASNs for the requested window.
func QueryTopASNAny(db *sql.DB, n, minutes int) (topIn, topOut []ASNStat) {
	if minutes <= MaxRingMinutes && Global != nil {
		return Global.QueryTopASN(n, minutes)
	}
	topIn, topOut, _ = QueryTopASNFromDB(db, n, minutes)
	return
}

// QueryInterfacesAny returns per-interface series for the requested window.
func QueryInterfacesAny(db *sql.DB, minutes int) []IfaceSeries {
	if minutes <= MaxRingMinutes && Global != nil {
		return Global.QueryInterfaces(minutes)
	}
	result, _ := QueryInterfacesFromDB(db, minutes)
	return result
}

// ── SQLite query implementations ─────────────────────────────────────────────

// QueryTimeSeriesFromDB returns minute-level throughput buckets from SQLite.
func QueryTimeSeriesFromDB(db *sql.DB, minutes int) ([]MinuteBucket, error) {
	cutoff := (time.Now().Unix()/60)*60 - int64(minutes-1)*60
	rows, err := db.Query(`
		SELECT ts, bytes_in, bytes_out, flows_in, flows_out, pkts_in, pkts_out
		FROM telemetry_buckets
		WHERE ts >= ?
		ORDER BY ts ASC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MinuteBucket
	for rows.Next() {
		var b MinuteBucket
		if err := rows.Scan(&b.Ts, &b.BytesIn, &b.BytesOut, &b.FlowsIn, &b.FlowsOut, &b.PktsIn, &b.PktsOut); err != nil {
			continue
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

// QueryTopASNFromDB aggregates ASN traffic over the requested window from SQLite.
// Returns top N by bytes_in and top N by bytes_out.
func QueryTopASNFromDB(db *sql.DB, n, minutes int) (topIn, topOut []ASNStat, err error) {
	cutoff := (time.Now().Unix()/60)*60 - int64(minutes-1)*60

	rows, err := db.Query(`
		SELECT asn,
		       MAX(name) as name,
		       SUM(bytes_in)  as bytes_in,
		       SUM(bytes_out) as bytes_out,
		       SUM(flows_in)  as flows_in,
		       SUM(flows_out) as flows_out
		FROM telemetry_asn_buckets
		WHERE ts >= ?
		GROUP BY asn
	`, cutoff)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var all []ASNStat
	for rows.Next() {
		var s ASNStat
		if err := rows.Scan(&s.ASN, &s.Name, &s.BytesIn, &s.BytesOut, &s.FlowsIn, &s.FlowsOut); err != nil {
			continue
		}
		all = append(all, s)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Sort copies for in/out independently
	in := make([]ASNStat, len(all))
	copy(in, all)
	sort.Slice(in, func(i, j int) bool { return in[i].BytesIn > in[j].BytesIn })
	if len(in) > n {
		in = in[:n]
	}

	out := make([]ASNStat, len(all))
	copy(out, all)
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	if len(out) > n {
		out = out[:n]
	}

	return in, out, nil
}

// QueryInterfacesFromDB returns per-interface series from SQLite.
func QueryInterfacesFromDB(db *sql.DB, minutes int) ([]IfaceSeries, error) {
	cutoff := (time.Now().Unix()/60)*60 - int64(minutes-1)*60

	rows, err := db.Query(`
		SELECT ts, iface_idx, name, bytes_in, bytes_out, flows_in, flows_out
		FROM telemetry_iface_buckets
		WHERE ts >= ?
		ORDER BY iface_idx, ts ASC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totals := make(map[uint32]*IfaceSeries)
	buckets := make(map[uint32][]IfaceMinBucket)

	for rows.Next() {
		var (
			ts                         int64
			idx                        uint32
			name                       string
			bytesIn, bytesOut          uint64
			flowsIn, flowsOut          uint64
		)
		if err := rows.Scan(&ts, &idx, &name, &bytesIn, &bytesOut, &flowsIn, &flowsOut); err != nil {
			continue
		}
		if totals[idx] == nil {
			totals[idx] = &IfaceSeries{Index: idx, Name: name}
		}
		if totals[idx].Name == "" && name != "" {
			totals[idx].Name = name
		}
		totals[idx].TotalIn += bytesIn
		totals[idx].TotalOut += bytesOut
		totals[idx].FlowsIn += flowsIn
		totals[idx].FlowsOut += flowsOut
		buckets[idx] = append(buckets[idx], IfaceMinBucket{
			Ts: ts, BytesIn: bytesIn, BytesOut: bytesOut,
			FlowsIn: flowsIn, FlowsOut: flowsOut,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]IfaceSeries, 0, len(totals))
	for idx, tot := range totals {
		s := *tot
		s.Series = buckets[idx]
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return (result[i].TotalIn + result[i].TotalOut) > (result[j].TotalIn + result[j].TotalOut)
	})
	return result, nil
}
