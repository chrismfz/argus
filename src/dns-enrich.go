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

func StartPTRResolver(cfg *config.Config) {
    resolver := enrich.NewDNSResolver(cfg.DNS.Nameserver)
    log.Printf("[INFO] DNS (PTR) enrichment is enabled with resolver: %s", cfg.DNS.Nameserver)

    // Ensure ptr_cache table exists
    if err := clickhouse.EnsureTables(); err != nil {
        log.Fatalf("[PTR] Failed to ensure tables: %v", err)
    }

    // === NEW: read from config with sensible defaults ===
    bs := cfg.DNS.BatchSize
    if bs <= 0 {
        bs = 200
    }

    interval := time.Duration(cfg.DNS.SecondsInterval) * time.Second
    if interval <= 0 {
        interval = 2 * time.Second
    }

    lookback := cfg.DNS.LookbackMinutes
    if lookback <= 0 {
        lookback = 60
    }

    maxThreads := cfg.DNS.MaxThreads
    if maxThreads <= 0 {
        maxThreads = 2
    }

    skipPrivate := cfg.DNS.SkipPrivate

    go func() {
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        for {
            processPTRBatch(resolver, bs, lookback, maxThreads, skipPrivate)
            <-ticker.C
        }
    }()
}

func processPTRBatch(resolver *enrich.DNSResolver, batchSize, lookbackMin, maxThreads int, skipPrivate bool) {
    ctx := context.Background()
    table := fmt.Sprintf("%s.%s", config.AppConfig.ClickHouse.Database, config.AppConfig.ClickHouse.Table)

    if batchSize <= 0 {
        batchSize = 200
    }
    if lookbackMin <= 0 {
        lookbackMin = 60
    }
    if maxThreads <= 0 {
        maxThreads = 2
    }

    // Προαιρετικό φίλτρο για private/LL IPs
    privateFilter := ""
    if skipPrivate {
        // IPv4: 10/8, 172.16-31/12, 192.168/16, 127/8 | IPv6: fc00/fd00 (ULA), fe80 (LL)
        privateFilter = `
          AND NOT match(ip, '^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^127\\.')
          AND NOT match(ip, '^(fc00:|fd00:|fe80:)')
        `
    }

    query := fmt.Sprintf(`
        SELECT s.ip
        FROM (
            SELECT src_host AS ip
            FROM %s
            WHERE timestamp_start >= now() - INTERVAL %d MINUTE
            UNION ALL
            SELECT dst_host AS ip
            FROM %s
            WHERE timestamp_start >= now() - INTERVAL %d MINUTE
        ) AS s
        LEFT JOIN ptr_cache AS p ON s.ip = p.ip
        WHERE p.ip IS NULL
          AND s.ip != '' %s
        GROUP BY s.ip
        LIMIT %d
        SETTINGS max_threads=%d
    `, table, lookbackMin, table, lookbackMin, privateFilter, batchSize, maxThreads)

    rows, err := clickhouse.Global.Query(ctx, query)
    if err != nil {
        log.Printf("[PTR][ERROR] SELECT failed: %v", err)
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
        log.Printf("[PTR] No candidate IPs for PTR in last %d minutes", lookbackMin)
        return
    }

    log.Printf("[PTR] Resolving PTR for %d IPs (lookback=%d min, skipPrivate=%v)",
        len(ipList), lookbackMin, skipPrivate)

    records := make([]clickhouse.PTRRecord, 0, len(ipList))
    for _, ip := range ipList {
        ptr := resolver.LookupPTR(ip)
        if ptr == "" {
            ptr = enrich.NoPTR
        }

        // 🔐 SAFE χρήση του geo: μπορεί να είναι nil αν δεν είναι ενεργό το "geoip"
        var asn uint32
        var asnName, country string
        if geo != nil {
            asn = geo.GetASNNumber(ip)
            asnName = geo.GetASNName(ip)
            country = geo.GetCountry(ip)
        }

        records = append(records, clickhouse.PTRRecord{
            IP:      ip,
            PTR:     ptr,
            ASN:     asn,
            ASNName: asnName,
            Country: country,
        })
    }

    if err := clickhouse.InsertPTRBatch(records); err != nil {
        log.Printf("[PTR][ERROR] batch insert failed: %v", err)
    } else {
        log.Printf("[PTR] Inserted %d PTR records into ptr_cache", len(records))
    }
}
