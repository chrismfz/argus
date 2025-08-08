// 📁 clickhouse/client.go
package clickhouse

import (
        "context"
        "fmt"
        "sync"
        "time"

        ch "github.com/ClickHouse/clickhouse-go/v2"
        "flowenricher/config"
)

var (
        Global ch.Conn
        once sync.Once
)

// ✅ Init global ClickHouse connection
func Init(cfg config.Config) error {
        var err error
        once.Do(func() {
                Global, err = ch.Open(&ch.Options{
                        Addr: []string{cfg.ClickHouse.Host + ":9000"},
                        Auth: ch.Auth{
                                Database: cfg.ClickHouse.Database,
                                Username: cfg.ClickHouse.User,
                                Password: cfg.ClickHouse.Password,
                        },
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
        }

        for name, ddl := range tables {
                if err := Global.Exec(ctx, ddl); err != nil {
                        return fmt.Errorf("create table %s: %w", name, err)
                }
        }
        return nil
}

// ✅ Struct for PTR batch insert
type PTRRecord struct {
        IP       string
        PTR      string
        ASN      uint32
        ASNName  string
        Country  string
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
