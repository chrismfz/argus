package enrich

import (
    "log"
    "time"
    "argus/internal/clickhouse"
)

func StartSNMPStatsCollector() {
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()

        for {
            <-ticker.C
            records, err := CollectSNMPStats()
            if err != nil {
                log.Printf("[SNMPStats] Failed to collect: %v", err)
                continue
            }

            if len(records) == 0 {
                log.Printf("[SNMPStats] No records to insert")
                continue
            }

            err = clickhouse.InsertSNMPStats(records)
            if err != nil {
                log.Printf("[SNMPStats] Insert failed: %v", err)
            } else {
                log.Printf("[SNMPStats] Inserted %d rows", len(records))
            }
        }
    }()
}
