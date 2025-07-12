// main.go
package main

import (
        "context"
        "fmt"
        "log"
        "os"
        "os/signal"
        "syscall"
        "time"
)

var debug bool
var showFlows bool

var Stats struct {
        Parsed         int
        PTRLookups     int
        Inserted       int
        EnrichDuration time.Duration
        InsertDuration time.Duration

        StartTime      time.Time
        EnrichDone     time.Time
        InsertDone     time.Time
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

        for _, arg := range os.Args[1:] {
                switch arg {
                case "--test":
                        testMode = true
                case "--debug":
                        debug = true
                case "--show-flows":
                        showFlows = true
                default:
                        configPath = arg
                }
        }

        cfg, err := LoadConfig(configPath)
        if err != nil {
                log.Fatalf("Error loading config: %v", err)
        }
        debug = debug || cfg.Debug

        Stats.StartTime = time.Now()

        dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
        dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
        if cfg.GeoIP.CityDB != "" {
                dlog("GeoIP City DB: %s", cfg.GeoIP.CityDB)
        }
        if cfg.DNS.Nameserver != "" {
                dlog("Using DNS resolver: %s", cfg.DNS.Nameserver)
        }

        bgp := NewBGPTable(cfg.BGP.TableFile)
        geo, err := NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
        if err != nil {
                log.Fatalf("GeoIP init error: %v", err)
        }
        resolver := NewDNSResolver(cfg.DNS.Nameserver)

        inserter, err := NewClickHouseInserter(cfg)
        if err != nil {
                log.Fatalf("ClickHouse connection error: %v", err)
        }
        dlog("ClickHouse connection established.")

        if testMode {
                runTestMode(cfg, geo, bgp, resolver)
                return
        }

        ctx, cancel := context.WithCancel(context.Background())
        go handleSignals(cancel)

        err = TailFileAndProcess(ctx, cfg.Input.LogFile, geo, bgp, resolver, cfg, inserter)
        if err != nil {
                log.Fatalf("Tail error: %v", err)
        }

        Stats.InsertDone = time.Now()
        printSummary()
}

func handleSignals(cancel context.CancelFunc) {
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
        <-sigChan
        fmt.Println("\nInterrupt received, exiting gracefully...")
        cancel()
}

func printSummary() {
        if debug {
                total := time.Since(Stats.StartTime)
                enrichDur := Stats.EnrichDone.Sub(Stats.StartTime)
                insertDur := Stats.InsertDone.Sub(Stats.EnrichDone)
                fmt.Println("--- FLOW ENRICHMENT SUMMARY ---")
                fmt.Printf("Parsed: %d\n", Stats.Parsed)
                fmt.Printf("PTR lookups: %d\n", Stats.PTRLookups)
                fmt.Printf("Inserted: %d\n", Stats.Inserted)
                fmt.Printf("Enrichment time: %s\n", enrichDur)
                fmt.Printf("Insert time: %s\n", insertDur)
                fmt.Printf("Total duration: %s\n", total)
                fmt.Println("--------------------------------")
        }
}

func runTestMode(cfg *Config, geo *GeoIP, bgp *BGPTable, resolver *DNSResolver) {
        dlog("Running in test mode...")
        sample := `{"timestamp_start": "2025-07-12 14:05:00.123456", "event_type": "purge", "ip_proto": "tcp", "ip_src": "8.8.8.8", "ip_dst": "1.1.1.1", "port_src": 12345, "port_dst": 443, "packets": 5, "bytes": 1500, "tcp_flags": 16, "tos": 0}`

        Stats.StartTime = time.Now()
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
        Stats.EnrichDone = time.Now()

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
        Stats.InsertDone = time.Now()

        fmt.Println("Test insert completed.")
        printSummary()
        os.Exit(0)
}
