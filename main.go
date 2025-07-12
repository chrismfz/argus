package main

import (
	"context"
	"fmt"
	"log"
	"os"
)

var debug bool

// Counters for debug summary
var Stats struct {
	Parsed     int
	PTRLookups int
	Inserted   int
}

func dlog(msg string, args ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func main() {
	var (
		configPath = "config.yaml"
		testMode   = false
	)

	// Handle CLI arguments
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--test":
			testMode = true
		case "--debug":
			debug = true
		default:
			configPath = arg // assume it's config path
		}
	}

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	debug = debug || cfg.Debug

	dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
	dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
	fmt.Println("Config loaded successfully.")

	// Init components
	bgp := NewBGPTable(cfg.BGP.TableFile)
	geo, err := NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
	if err != nil {
		log.Fatalf("GeoIP init error: %v", err)
	}
	resolver := NewDNSResolver(cfg.DNS.Nameserver)

	if testMode {
		dlog("Running in test mode...")
		sample := `{"timestamp_start": "2025-07-12 14:05:00.123456", "event_type": "purge", "ip_proto": "tcp", "ip_src": "8.8.8.8", "ip_dst": "1.1.1.1", "port_src": 12345, "port_dst": 443, "packets": 5, "bytes": 1500, "tcp_flags": 16, "tos": 0}`

		rec, err := ParseAndEnrich(sample, geo, bgp, resolver, cfg.Timezone)
		if err != nil {
			log.Fatalf("Parse error: %v", err)
		}
		Stats.Parsed++
		if rec.SrcHostPTR != "" {
			Stats.PTRLookups++
		}
		if rec.DstHostPTR != "" {
			Stats.PTRLookups++
		}

		fmt.Printf("Parsed: %+v\n", rec)

		inserter, err := NewClickHouseInserter(cfg)
		if err != nil {
			log.Fatalf("ClickHouse error: %v", err)
		}

		ctx := context.Background()
		if err := inserter.InsertFlow(ctx, rec); err != nil {
			log.Fatalf("Insert error: %v", err)
		}
		Stats.Inserted++
		fmt.Println("Test insert completed.")

		if debug {
			fmt.Printf("[SUMMARY] Parsed %d flows, resolved %d PTRs, inserted %d records\n",
				Stats.Parsed, Stats.PTRLookups, Stats.Inserted)
		}

		os.Exit(0)
	}

	// PRODUCTION MODE: tail flows and insert
	inserter, err := NewClickHouseInserter(cfg)
	if err != nil {
		log.Fatalf("ClickHouse error: %v", err)
	}

	if err := TailFileAndProcess(cfg.Input.LogFile, geo, bgp, resolver, cfg, inserter); err != nil {
		log.Fatalf("Tail error: %v", err)
	}

	if debug {
		fmt.Printf("[SUMMARY] Parsed %d flows, resolved %d PTRs, inserted %d records\n",
			Stats.Parsed, Stats.PTRLookups, Stats.Inserted)
	}
}
