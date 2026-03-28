// detection/clickhouse_writer.go
package detection

import (
	"context"
	"fmt"
	"net"
	"time"

	"argus/clickhouse"
	"argus/config"
)

type ClickHouseWriter struct{}

func NewClickHouseWriter() *ClickHouseWriter { return &ClickHouseWriter{} }

func (w *ClickHouseWriter) table() string {
	db := "default"
	if config.AppConfig != nil && config.AppConfig.ClickHouse.Database != "" {
		db = config.AppConfig.ClickHouse.Database
	}
	return db + ".detections"
}

// toIPString returns a clean IPv4 string for IPv4 inputs (e.g. "103.56.61.130")
// and a canonical IPv6 string for IPv6 inputs.
func toIPString(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s // fallback: return as-is
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// Upsert-like snapshot: γράφουμε νέα έκδοση (ReplacingMergeTree με version).
func (w *ClickHouseWriter) UpsertDetectionSnapshot(
	srcIP string,
	rule DetectionRule,
	proto string,
	dstPort uint16,
	exampleDstIP string,
	alerts uint64,    // συνολικός μετρητής (SQLite)
	lastFlows uint32, // len(flows) του match
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

	tbl := w.table()
	q := fmt.Sprintf(`
		INSERT INTO %s (
			src_ip, rule, proto, src_asn, src_asn_name, country, ptr,
			alerts, last_flows, first_seen, last_seen,
			example_dst_ip, example_dst_port, version
		)
	`, tbl)

	batch, err := clickhouse.Global.PrepareBatch(ctx, q)
	if err != nil {
		return err
	}

	if err := batch.Append(
		toIPString(srcIP),        // String: καθαρό IPv4/IPv6
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
		toIPString(exampleDstIP), // String: καθαρό IPv4/IPv6
		dstPort,                  // UInt16: πραγματικό παράδειγμα port από το flow
		nowVer,
	); err != nil {
		return err
	}

	return batch.Send()
}
