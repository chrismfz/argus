package enrich

import (
	"argus/internal/config"
	"log"
)

// StartPTRResolver previously ran a background goroutine that queried
// ClickHouse for unresolved IPs and wrote PTR records to ptr_cache.
//
// With ClickHouse removed, batch PTR resolution is disabled. PTR lookups
// still happen on-demand via DNSResolver.LookupPTR() — used by the
// detection engine (LogDetection) and the /infoip API endpoint.
//
// If you want PTR enrichment on flows again, it can be wired into the
// telemetry aggregator's top-hosts query instead.
func StartPTRResolver(cfg *config.Config, geoIP *GeoIP, debugMode bool) {
	log.Printf("[PTR] batch PTR resolver disabled (ClickHouse removed). on-demand PTR via DNS resolver=%s still active.", cfg.DNS.Nameserver)
}
