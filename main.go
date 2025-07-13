package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"
)

var debug bool
var showFlows bool
var geo *GeoIP
var bgp *BGPTable
var resolver *DNSResolver

func dlog(msg string, args ...interface{}) {
    if debug {
        log.Printf("[DEBUG] "+msg, args...)
    }
}

func main() {
    var configPath = "config.yaml"

    for _, arg := range os.Args[1:] {
        switch arg {
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

    dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
    dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
    if cfg.GeoIP.CityDB != "" {
        dlog("GeoIP City DB: %s", cfg.GeoIP.CityDB)
    }
    if cfg.DNS.Nameserver != "" {
        dlog("Using DNS resolver: %s", cfg.DNS.Nameserver)
    }

    // Enrichment modules (conditionally initialized)
    if enrichEnabled(cfg, "geoip") {
        geo, err = NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
        if err != nil {
            log.Fatalf("GeoIP init error: %v", err)
        }
    }

    if enrichEnabled(cfg, "bgp") {
        bgp = NewBGPTable(cfg.BGP.TableFile)
    }

    if enrichEnabled(cfg, "ptr") {
        resolver = NewDNSResolver(cfg.DNS.Nameserver)
    }

    inserter, err := NewClickHouseInserter(cfg)
    if err != nil {
        log.Fatalf("ClickHouse connection error: %v", err)
    }
    dlog("ClickHouse connection established.")

    ctx, cancel := context.WithCancel(context.Background())
    go handleSignals(cancel)


batcher := NewInsertFlowBatcher(
    inserter,
    cfg.Insert.BatchSize,
    time.Duration(cfg.Insert.FlushIntervalMs)*time.Millisecond,
    bgp,
)
defer batcher.Close()



    err = StartKafkaConsumer(ctx, cfg, geo, bgp, resolver, batcher)
    if err != nil {
        log.Fatalf("Kafka consumer error: %v", err)
    }
}

func handleSignals(cancel context.CancelFunc) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    <-sigChan
    log.Println("Interrupt received, exiting gracefully...")
    cancel()
}

func enrichEnabled(cfg *Config, name string) bool {
    if strings.ToLower(cfg.Enrich) == "none" {
        return false
    }
    parts := strings.Split(strings.ToLower(cfg.Enrich), ",")
    for _, p := range parts {
        if strings.TrimSpace(p) == name {
            return true
        }
    }
    return false
}
