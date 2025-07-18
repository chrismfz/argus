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
	ptrPlaceholder = "NoPTR"
	batchSize      = 20
	sleepInterval  = 10 * time.Second
)

func StartPTRResolver(cfg *config.Config) {
	resolver := NewDNSResolver(cfg.DNS.Nameserver)


log.Printf("[INFO] DNS (PTR) Enrichment is enabled with Resolver: %s", cfg.DNS.Nameserver)

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
			processPTRBatch(db, resolver, cfg.ClickHouse.Table, "src_host", "src_host_ptr")
			processPTRBatch(db, resolver, cfg.ClickHouse.Table, "dst_host", "dst_host_ptr")
			time.Sleep(sleepInterval)
		}
	}()
}

func processPTRBatch(db *sql.DB, resolver *DNSResolver, table, ipField, ptrField string) {
	ctx := context.Background()

	query := fmt.Sprintf("SELECT DISTINCT %s FROM %s WHERE %s = '' LIMIT %d", ipField, table, ptrField, batchSize)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		dlog("[PTR][ERROR] SELECT failed for %s: %v", ipField, err)
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

	for _, ip := range ipList {
		ptr := resolver.LookupPTR(ip)
		if ptr == "" {
			ptr = ptrPlaceholder
		}

		update := fmt.Sprintf("ALTER TABLE %s UPDATE %s = ? WHERE %s = ?", table, ptrField, ipField)
		if _, err := db.ExecContext(ctx, update, ptr, ip); err != nil {
			dlog("[PTR][ERROR] UPDATE failed for IP %s: %v", ip, err)
		} else {
			dlog("[PTR] Updated %s for %s: %s", ptrField, ip, ptr)
		}
	}
}
