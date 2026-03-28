// 📁 clickhouse/client.go
package clickhouse

import (
	"context"
	"fmt"
	"sync"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"argus/internal/config"
)

var (
	Global ch.Conn
	once   sync.Once
)

// ✅ Init global ClickHouse connection
func Init(cfg config.Config) error {
	var err error
	once.Do(func() {
		Global, err = ch.Open(&ch.Options{
			Addr:        []string{cfg.ClickHouse.Host + ":9000"},
			Auth:        ch.Auth{Database: cfg.ClickHouse.Database, Username: cfg.ClickHouse.User, Password: cfg.ClickHouse.Password},
			DialTimeout: 5 * time.Second,
		})
	})
	return err
}

// ✅ Ensure all required tables exist or are valid
func EnsureTables() error {
	ctx := context.Background()

	tables := map[string]string{
		"ptr_cache": `
			CREATE TABLE IF NOT EXISTS ptr_cache (
				ip String,
				ptr String,
				updated_at DateTime DEFAULT now(),
				asn UInt32 DEFAULT 0,
				asn_name String DEFAULT '',
				country String DEFAULT ''
			) ENGINE = MergeTree
			ORDER BY ip`,

		"snmp_stats": `
			CREATE TABLE IF NOT EXISTS snmp_stats (
				timestamp DateTime,
				if_index UInt32,
				if_name String,
				rx_bytes UInt64,
				tx_bytes UInt64,
				rx_packets UInt64,
				tx_packets UInt64,
				admin_status UInt8,
				oper_status UInt8,
				if_type UInt64,
				if_type_str String
			) ENGINE = MergeTree
			ORDER BY (timestamp, if_index)`,

		// 💡 detections με IPv6 στήλες (μένει ως έχει)
		"detections": `
			CREATE TABLE IF NOT EXISTS detections (
				src_ip           IPv6,
				rule             LowCardinality(String),
				proto            LowCardinality(String),
				src_asn          UInt32,
				src_asn_name     LowCardinality(String),
				country          FixedString(2),
				ptr              String,
				alerts           UInt64,
				last_flows       UInt32,
				first_seen       DateTime,
				last_seen        DateTime,
				example_dst_ip   IPv6,
				example_dst_port UInt16,
				version          UInt64
			)
			ENGINE = ReplacingMergeTree(version)
			PARTITION BY toDate(first_seen)
			ORDER BY (src_ip, rule)`,
	}

	for name, ddl := range tables {
		if err := Global.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("create table %s: %w", name, err)
		}
	}

	// 🔎 Ensure view (ΜΕΣΑ στη function, χρησιμοποιούμε Global)
	viewDDL := `
		CREATE OR REPLACE VIEW detections_view AS
		SELECT
		  replaceRegexpOne(IPv6NumToString(src_ip), '^::ffff:', '')  AS src_ip,
		  rule, proto, src_asn, src_asn_name, country, ptr,
		  alerts, last_flows, first_seen, last_seen,
		  replaceRegexpOne(IPv6NumToString(example_dst_ip), '^::ffff:', '') AS example_dst_ip,
		  example_dst_port, version
		FROM detections`
	if err := Global.Exec(ctx, viewDDL); err != nil {
		return fmt.Errorf("ensure view detections_view: %w", err)
	}

	return nil
}

// ✅ Struct for PTR batch insert
type PTRRecord struct {
	IP      string
	PTR     string
	ASN     uint32
	ASNName string
	Country string
}

func InsertPTRBatch(records []PTRRecord) error {
	ctx := context.Background()
	batch, err := Global.PrepareBatch(ctx, `INSERT INTO ptr_cache (ip, ptr, asn, asn_name, country)`)
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := batch.Append(r.IP, r.PTR, r.ASN, r.ASNName, r.Country); err != nil {
			return err
		}
	}
	return batch.Send()
}

// ✅ Struct for SNMP insert
type SNMPStat struct {
	Timestamp    time.Time
	IfIndex      uint32
	IfName       string
	RxBytes      uint64
	TxBytes      uint64
	RxPackets    uint64
	TxPackets    uint64
	AdminStatus  uint8
	OperStatus   uint8
	IfType       uint64
	IfTypeString string
}

func InsertSNMPStats(records []SNMPStat) error {
	ctx := context.Background()
	batch, err := Global.PrepareBatch(ctx, `
		INSERT INTO snmp_stats (
			timestamp, if_index, if_name,
			rx_bytes, tx_bytes,
			rx_packets, tx_packets,
			admin_status, oper_status,
			if_type, if_type_str
		)`)
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := batch.Append(
			r.Timestamp,
			r.IfIndex,
			r.IfName,
			r.RxBytes,
			r.TxBytes,
			r.RxPackets,
			r.TxPackets,
			r.AdminStatus,
			r.OperStatus,
			r.IfType,
			r.IfTypeString,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}
