package mailwatch

import (
	"database/sql"
	"encoding/json"
	"sort"
	"time"
)

// SenderSummary is one sender over a query window, joined with its long-lived
// memory row.
type SenderSummary struct {
	IP          string   `json:"ip"`
	Ports       []int    `json:"ports"`
	Flows       uint64   `json:"flows"`
	Bytes       uint64   `json:"bytes"`
	Buckets     int      `json:"buckets"`        // active buckets in the window
	PeakDsts    int      `json:"peak_uniq_dsts"` // busiest bucket in the window
	Capped      bool     `json:"capped,omitempty"`
	FirstSeen   int64    `json:"first_seen"`
	LastSeen    int64    `json:"last_seen"`
	TotalFlows  uint64   `json:"total_flows"`
	MaxDstsEver int      `json:"max_uniq_dsts_ever"`
	PTR         string   `json:"ptr,omitempty"`
	Spark       []uint64 `json:"spark,omitempty"` // flows per bucket over the window, oldest first
}

// Senders lists every sender active since `since`, busiest first.
func Senders(db *sql.DB, since time.Time, bucket time.Duration, limit int) ([]SenderSummary, error) {
	if bucket <= 0 {
		bucket = 5 * time.Minute
	}
	from := since.Truncate(bucket).Unix()
	rows, err := db.Query(`
		SELECT b.src_ip, b.port, b.ts, b.flows, b.bytes, b.uniq_dsts, b.capped,
		       COALESCE(s.first_seen, 0), COALESCE(s.last_seen, 0),
		       COALESCE(s.total_flows, 0), COALESCE(s.max_uniq_dsts, 0)
		FROM mail_egress_buckets b
		LEFT JOIN mail_egress_senders s ON s.src_ip = b.src_ip
		WHERE b.ts >= ?
		ORDER BY b.ts`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nBuckets := int((time.Now().Truncate(bucket).Unix()-from)/int64(bucket.Seconds())) + 1
	byIP := map[string]*SenderSummary{}
	ports := map[string]map[int]bool{}
	seenTs := map[string]map[int64]bool{}
	for rows.Next() {
		var (
			ip              string
			port, dsts, cpd int
			ts              int64
			flows, bytes    uint64
			first, last     int64
			total           uint64
			maxEver         int
		)
		if err := rows.Scan(&ip, &port, &ts, &flows, &bytes, &dsts, &cpd, &first, &last, &total, &maxEver); err != nil {
			return nil, err
		}
		s := byIP[ip]
		if s == nil {
			s = &SenderSummary{IP: ip, FirstSeen: first, LastSeen: last, TotalFlows: total,
				MaxDstsEver: maxEver, Spark: make([]uint64, nBuckets)}
			byIP[ip] = s
			ports[ip] = map[int]bool{}
			seenTs[ip] = map[int64]bool{}
		}
		s.Flows += flows
		s.Bytes += bytes
		if dsts > s.PeakDsts {
			s.PeakDsts = dsts
		}
		s.Capped = s.Capped || cpd == 1
		ports[ip][port] = true
		if !seenTs[ip][ts] {
			seenTs[ip][ts] = true
			s.Buckets++
		}
		if i := int((ts - from) / int64(bucket.Seconds())); i >= 0 && i < nBuckets {
			s.Spark[i] += flows
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]SenderSummary, 0, len(byIP))
	for ip, s := range byIP {
		for p := range ports[ip] {
			s.Ports = append(s.Ports, p)
		}
		sort.Ints(s.Ports)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].IP < out[j].IP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// BucketRow is one stored bucket of a single sender.
type BucketRow struct {
	Ts       int64    `json:"ts"`
	Port     int      `json:"port"`
	Flows    uint64   `json:"flows"`
	Packets  uint64   `json:"packets"`
	Bytes    uint64   `json:"bytes"`
	UniqDsts int      `json:"uniq_dsts"`
	UniqASNs int      `json:"uniq_asns"`
	Capped   bool     `json:"capped,omitempty"`
	TopDsts  []TopDst `json:"top_dsts"`
	TopASNs  []TopASN `json:"top_asns"`
}

// SenderHistory is the per-IP drill-down: memory row, timeline, and the top
// destinations/ASNs merged over the window (approximate: each bucket only
// keeps its own top-N).
type SenderHistory struct {
	IP          string      `json:"ip"`
	Known       bool        `json:"known"`
	FirstSeen   int64       `json:"first_seen,omitempty"`
	LastSeen    int64       `json:"last_seen,omitempty"`
	TotalFlows  uint64      `json:"total_flows"`
	TotalBytes  uint64      `json:"total_bytes"`
	MaxDstsEver int         `json:"max_uniq_dsts_ever"`
	PTR         string      `json:"ptr,omitempty"`
	Buckets     []BucketRow `json:"buckets"`
	TopDsts     []TopDst    `json:"top_dsts"`
	TopASNs     []TopASN    `json:"top_asns"`
}

// History returns one sender's buckets since `since` plus merged top lists.
func History(db *sql.DB, ip string, since time.Time, topN int) (*SenderHistory, error) {
	if topN <= 0 {
		topN = 20
	}
	h := &SenderHistory{IP: ip, Buckets: []BucketRow{}}
	err := db.QueryRow(`SELECT first_seen, last_seen, total_flows, total_bytes, max_uniq_dsts
		FROM mail_egress_senders WHERE src_ip = ?`, ip).
		Scan(&h.FirstSeen, &h.LastSeen, &h.TotalFlows, &h.TotalBytes, &h.MaxDstsEver)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return nil, err
	default:
		h.Known = true
	}

	rows, err := db.Query(`
		SELECT ts, port, flows, packets, bytes, uniq_dsts, uniq_asns, capped, top_dsts, top_asns
		FROM mail_egress_buckets WHERE src_ip = ? AND ts >= ? ORDER BY ts`, ip, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dsts := map[string]uint64{}
	asns := map[uint32]*asnAgg{}
	for rows.Next() {
		var b BucketRow
		var capped int
		var td, ta string
		if err := rows.Scan(&b.Ts, &b.Port, &b.Flows, &b.Packets, &b.Bytes, &b.UniqDsts, &b.UniqASNs, &capped, &td, &ta); err != nil {
			return nil, err
		}
		b.Capped = capped == 1
		_ = json.Unmarshal([]byte(td), &b.TopDsts)
		_ = json.Unmarshal([]byte(ta), &b.TopASNs)
		for _, d := range b.TopDsts {
			dsts[d.IP] += d.Flows
		}
		for _, a := range b.TopASNs {
			if x := asns[a.ASN]; x != nil {
				x.flows += a.Flows
			} else {
				asns[a.ASN] = &asnAgg{name: a.Name, flows: a.Flows}
			}
		}
		h.Buckets = append(h.Buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	h.TopDsts = topDsts(dsts, topN)
	h.TopASNs = topASNs(asns, topN)
	return h, nil
}
