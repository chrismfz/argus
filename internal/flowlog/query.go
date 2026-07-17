package flowlog

import (
	"strconv"
	"strings"
)

// Filter selects flows for a query. All fields are optional (zero = ignore);
// a non-empty IP matches src OR dst, while SrcIP/DstIP pin a side.
type Filter struct {
	IP       string
	SrcIP    string
	DstIP    string
	Proto    uint8
	HasProto bool
	Port     uint16
	HasPort  bool
	Dir      string // "in" | "out"
	Since    int64  // unix seconds, inclusive
	Until    int64  // unix seconds, inclusive
	Limit    int    // default 1000, capped at 100000
}

// Query returns matching flows, newest first. Read-only; safe to call from the
// API while the writer is running (separate connection, WAL).
func (l *Logger) Query(f Filter) ([]Row, error) {
	var where []string
	var args []interface{}

	if f.IP != "" {
		where = append(where, "(src_ip = ? OR dst_ip = ?)")
		args = append(args, f.IP, f.IP)
	}
	if f.SrcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, f.SrcIP)
	}
	if f.DstIP != "" {
		where = append(where, "dst_ip = ?")
		args = append(args, f.DstIP)
	}
	if f.HasProto {
		where = append(where, "proto = ?")
		args = append(args, f.Proto)
	}
	if f.HasPort {
		where = append(where, "(src_port = ? OR dst_port = ?)")
		args = append(args, f.Port, f.Port)
	}
	if f.Dir == "in" || f.Dir == "out" {
		where = append(where, "dir = ?")
		args = append(args, f.Dir)
	}
	if f.Since > 0 {
		where = append(where, "ts >= ?")
		args = append(args, f.Since)
	}
	if f.Until > 0 {
		where = append(where, "ts <= ?")
		args = append(args, f.Until)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	if limit > 100000 {
		limit = 100000
	}

	q := `SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags,
	             bytes, packets, in_iface, out_iface, src_as, dst_as, dir
	      FROM flows`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY ts DESC LIMIT " + strconv.Itoa(limit)

	rows, err := l.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(
			&r.Ts, &r.SrcIP, &r.DstIP, &r.SrcPort, &r.DstPort, &r.Proto, &r.TCPFlags,
			&r.Bytes, &r.Packets, &r.InIface, &r.OutIface, &r.SrcAS, &r.DstAS, &r.Dir,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Stats returns the row count and total on-disk file size, for the debug/status
// endpoint. Both errors are returned so the caller can surface them rather than
// reporting a misleading empty log.
func (l *Logger) Stats() (rowCount int64, bytes int64, err error) {
	if err = l.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&rowCount); err != nil {
		return
	}
	bytes, err = l.fileBytes()
	return
}
