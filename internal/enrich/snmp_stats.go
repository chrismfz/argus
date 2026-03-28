package enrich

import (
	"log"
	"time"
)

// SNMPStat holds one interface's counters at a point in time.
// Previously lived in internal/clickhouse — moved here now that CH is removed.
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

// StartSNMPStatsCollector runs a background poller.
// ClickHouse write has been removed — data is served live via /snmp/interfaces.
func StartSNMPStatsCollector() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			_, err := CollectSNMPStats()
			if err != nil {
				log.Printf("[SNMPStats] collect failed: %v", err)
			}
		}
	}()
}
