package main

import (
    "context"
    "fmt"
    "log"
    "time"

    ch "github.com/ClickHouse/clickhouse-go/v2"
    "flowenricher/config"
)

const (
    batchSize     = 200
    sleepInterval = 2 * time.Second
//    NoPTR         = "NoPTR" // Already defined in dns.go
)

func StartPTRResolver(cfg *config.Config) {
    resolver := NewDNSResolver(cfg.DNS.Nameserver)
    log.Printf("[INFO] DNS (PTR) enrichment is enabled with resolver: %s", cfg.DNS.Nameserver)

    conn, err := ch.Open(&ch.Options{
        Addr: []string{cfg.ClickHouse.Host + ":9000"},
        Auth: ch.Auth{
            Database: cfg.ClickHouse.Database,
            Username: cfg.ClickHouse.User,
            Password: cfg.ClickHouse.Password,
        },
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        log.Fatalf("[PTR] Failed to connect to ClickHouse: %v", err)
    }

    go func() {
        defer conn.Close()
        for {
            processPTRBatch(conn, resolver)
            time.Sleep(sleepInterval)
        }
    }()
}

func processPTRBatch(conn ch.Conn, resolver *DNSResolver) {
    ctx := context.Background()

    query := fmt.Sprintf(`
        SELECT DISTINCT ip FROM (
            SELECT DISTINCT src_host AS ip FROM pmacct.flows
            UNION ALL
            SELECT DISTINCT dst_host AS ip FROM pmacct.flows
        )
        WHERE ip NOT IN (SELECT ip FROM ptr_cache)
        LIMIT %d`, batchSize)

    rows, err := conn.Query(ctx, query)
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

    batch, err := conn.PrepareBatch(ctx, "INSERT INTO ptr_cache (ip, ptr, asn, asn_name, country)")
    if err != nil {
        log.Printf("[PTR][ERROR] prepare batch: %v", err)
        return
    }

    for _, ip := range ipList {
        ptr := resolver.LookupPTR(ip)
        if ptr == "" {
            ptr = NoPTR
        }

        asn := geo.GetASNNumber(ip)
        asnName := geo.GetASNName(ip)
        country := geo.GetCountry(ip)

        if err := batch.Append(ip, ptr, asn, asnName, country); err != nil {
            log.Printf("[PTR][ERROR] append failed for %s: %v", ip, err)
        }
    }

    if err := batch.Send(); err != nil {
        log.Printf("[PTR][ERROR] batch send failed: %v", err)
    }
}
