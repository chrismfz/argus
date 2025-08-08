// dns-enrich.go (updated)
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "flowenricher/config"
    "flowenricher/enrich"
    "flowenricher/clickhouse"
)

const (
    batchSize     = 200
    sleepInterval = 2 * time.Second
)

func StartPTRResolver(cfg *config.Config) {
    resolver := enrich.NewDNSResolver(cfg.DNS.Nameserver)
    log.Printf("[INFO] DNS (PTR) enrichment is enabled with resolver: %s", cfg.DNS.Nameserver)

    // Ensure ptr_cache table exists
    if err := clickhouse.EnsureTables(); err != nil {
        log.Fatalf("[PTR] Failed to ensure tables: %v", err)
    }

    go func() {
        for {
            processPTRBatch(resolver)
            time.Sleep(sleepInterval)
        }
    }()
}

func processPTRBatch(resolver *enrich.DNSResolver) {
    ctx := context.Background()
    table := fmt.Sprintf("%s.%s", config.AppConfig.ClickHouse.Database, config.AppConfig.ClickHouse.Table)

    query := fmt.Sprintf(`
        SELECT DISTINCT ip FROM (
            SELECT DISTINCT src_host AS ip FROM %s
            UNION ALL
            SELECT DISTINCT dst_host AS ip FROM %s
        )
        WHERE ip NOT IN (SELECT ip FROM ptr_cache)
        LIMIT %d`, table, table, batchSize)

    rows, err := clickhouse.Global.Query(ctx, query)
    if err != nil {
        log.Printf("[PTR][ERROR] SELECT DISTINCT failed: %v", err)
        return
    }
    defer rows.Close()

    var ipList []string
    for rows.Next() {
        var ip string
        if err := rows.Scan(&ip); err != nil {
            log.Printf("[PTR][ERROR] rows.Scan(): %v", err)
            continue
        }
        ipList = append(ipList, ip)
    }

    if len(ipList) == 0 {
        return
    }

    var records []clickhouse.PTRRecord
    for _, ip := range ipList {
        ptr := resolver.LookupPTR(ip)
        if ptr == "" {
            ptr = enrich.NoPTR
        }

        records = append(records, clickhouse.PTRRecord{
            IP:      ip,
            PTR:     ptr,
            ASN:     geo.GetASNNumber(ip),
            ASNName: geo.GetASNName(ip),
            Country: geo.GetCountry(ip),
        })
    }

    if err := clickhouse.InsertPTRBatch(records); err != nil {
        log.Printf("[PTR][ERROR] batch insert failed: %v", err)
    }
}
