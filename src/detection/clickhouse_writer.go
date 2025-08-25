// detection/clickhouse_writer.go
package detection

import (
	"context"
	"fmt"
	"net"
	"time"

	"flowenricher/clickhouse"
	"flowenricher/config"
)

type ClickHouseWriter struct{}

func NewClickHouseWriter() *ClickHouseWriter {
	return &ClickHouseWriter{}
}

func (w *ClickHouseWriter) table() string {
	// Παίρνουμε το table από το config, fallback "detections"
	if config.AppConfig != nil && config.AppConfig.ClickHouse.Table != "" {
		return config.AppConfig.ClickHouse.Table
	}
	return "detections"
}

func toIPv6Bytes(str string) []byte {
	ip := net.ParseIP(str)
	if ip == nil {
		return net.IPv6zero
	}
	ip = ip.To16()
	if ip == nil {
		return net.IPv6zero
	}
	return ip
}

// Upsert-like snapshot: γράφουμε νέα έκδοση (ReplacingMergeTree με version).
func (w *ClickHouseWriter) UpsertDetectionSnapshot(
	srcIP string,
	rule DetectionRule,
	proto string,
	dstPort uint16,
	exampleDstIP string,
	alerts uint64,     // συνολικός μετρητής που ήδη διατηρείς (SQLite)
	lastFlows uint32,  // len(flows) του τρέχοντος match
	asn uint32,
	asnName string,
	country string,
	ptr string,
	firstSeen time.Time,
	lastSeen time.Time,
) error {
	ctx := context.Background()
	nowVer := uint64(time.Now().Unix())

	if asnName == "" {
		asnName = "Unknown"
	}
	if country == "" {
		country = "--"
	}
	if ptr == "" {
		ptr = "-"
	}

	// Χρησιμοποιούμε την global σύνδεση που έχεις ήδη φτιάξει στο clickhouse/client.go
	// και το table name από config.
	tbl := w.table()
	q := fmt.Sprintf(`
		INSERT INTO %s (
			src_ip, rule, proto, src_asn, src_asn_name, country, ptr,
			alerts, last_flows, first_seen, last_seen,
			example_dst_ip, example_dst_port, version
		)`, tbl)

	batch, err := clickhouse.Global.PrepareBatch(ctx, q)
	if err != nil {
		return err
	}

	if err := batch.Append(
		toIPv6Bytes(srcIP),
		rule.Name,
		proto,
		asn,
		asnName,
		country,
		ptr,
		alerts,
		lastFlows,
		firstSeen,
		lastSeen,
		toIPv6Bytes(exampleDstIP),
		dstPort,
		nowVer,
	); err != nil {
		return err
	}

	return batch.Send()
}
