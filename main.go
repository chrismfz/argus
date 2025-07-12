package main

import (
	"fmt"
	"log"
	"os"
	"context"
)

var debug bool

func dlog(msg string, args ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	debug = cfg.Debug

	dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
	dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
	fmt.Println("Config loaded successfully.")

	// BGP Test
	bgp := NewBGPTable(cfg.BGP.TableFile)
	asPath := bgp.FindASPath("8.8.8.8")
	fmt.Printf("AS path for 8.8.8.8: %v\n", asPath)

	// GeoIP Test
	geo, err := NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
	if err != nil {
		log.Fatalf("GeoIP init error: %v", err)
	}

	ip := "8.8.8.8"
	fmt.Printf("ASN: %d (%s), Country: %s, City: %s\n",
		geo.GetASNNumber(ip),
		geo.GetASNName(ip),
		geo.GetCountry(ip),
		geo.GetCity(ip),
	)

	// PTR Test
	resolver := NewDNSResolver(cfg.DNS.Nameserver)
	fmt.Printf("PTR: %s\n", resolver.LookupPTR(ip))

line := `{"timestamp_start": "2025-07-12 14:05:00.123456", "event_type": "purge", "ip_proto": "tcp", "ip_src": "8.8.8.8", "ip_dst": "1.1.1.1", "port_src": 12345, "port_dst": 443, "packets": 5, "bytes": 1500, "tcp_flags": 16, "tos": 0}`
rec, err := ParseAndEnrich(line, geo, bgp, resolver, cfg.Timezone)
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Parsed: %+v\n", rec)



inserter, err := NewClickHouseInserter(cfg)
if err != nil {
	log.Fatalf("ClickHouse error: %v", err)
}

ctx := context.Background()
err = inserter.InsertFlow(ctx, rec)
if err != nil {
	log.Fatalf("Insert error: %v", err)
}

fmt.Println("Inserted successfully!")


inserter, err = NewClickHouseInserter(cfg)
if err != nil {
	log.Fatalf("ClickHouse error: %v", err)
}

if err := TailFileAndProcess(cfg.Input.LogFile, geo, bgp, resolver, cfg, inserter); err != nil {
	log.Fatalf("Tail error: %v", err)
}

}
