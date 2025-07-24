package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "time"

    _ "github.com/ClickHouse/clickhouse-go/v2"
    "flowenricher/config"
)

const (
    batchSize     = 200
    sleepInterval = 2 * time.Second
)

func StartPTRResolver(cfg *config.Config) {
    resolver := NewDNSResolver(cfg.DNS.Nameserver)

    log.Printf("[INFO] DNS (PTR) enrichment is enabled with resolver: %s", cfg.DNS.Nameserver)

    dsn := fmt.Sprintf("tcp://%s:9000?username=%s&password=%s&database=%s",
        cfg.ClickHouse.Host,
        cfg.ClickHouse.User,
        cfg.ClickHouse.Password,
        cfg.ClickHouse.Database,
    )
    db, err := sql.Open("clickhouse", dsn)
    if err != nil {
        log.Fatalf("[PTR] Failed to connect to ClickHouse: %v", err)
    }

    go func() {
        defer db.Close()
        for {
            processPTRBatch(db, resolver)
            time.Sleep(sleepInterval)
        }
    }()
}

func processPTRBatch(db *sql.DB, resolver *DNSResolver) {
    ctx := context.Background()

    query := fmt.Sprintf(`
        SELECT DISTINCT ip FROM (
            SELECT DISTINCT src_host AS ip FROM pmacct.flows
            UNION ALL
            SELECT DISTINCT dst_host AS ip FROM pmacct.flows
        )
        WHERE ip NOT IN (SELECT ip FROM ptr_cache)
        LIMIT %d`, batchSize)

    rows, err := db.QueryContext(ctx, query)
    if err != nil {
        dlog("[PTR][ERROR] SELECT DISTINCT failed: %v", err)
        return
    }
    defer rows.Close()

    var ipList []string
    for rows.Next() {
        var ip string
        if err := rows.Scan(&ip); err != nil {
            dlog("[PTR][ERROR] rows.Scan(): %v", err)
            continue
        }
        ipList = append(ipList, ip)
    }

    if len(ipList) == 0 {
        dlog("[PTR] No new IPs to resolve")
        return
    }

    tx, err := db.Begin()
    if err != nil {
        dlog("[PTR][ERROR] begin transaction: %v", err)
        return
    }

    stmt, err := tx.PrepareContext(ctx, "INSERT INTO ptr_cache (ip, ptr) VALUES (?, ?)")
    if err != nil {
        dlog("[PTR][ERROR] prepare insert: %v", err)
        return
    }
    defer stmt.Close()

    for _, ip := range ipList {
        ptr := resolver.LookupPTR(ip)
        if ptr == "" {
            ptr = NoPTR
        }

        if _, err := stmt.ExecContext(ctx, ip, ptr); err != nil {
            dlog("[PTR][ERROR] INSERT failed for %s: %v", ip, err)
        } else {
            dlog("[PTR] Cached PTR for %s: %s", ip, ptr)
        }
    }

    if err := tx.Commit(); err != nil {
        dlog("[PTR][ERROR] commit failed: %v", err)
    }
}
