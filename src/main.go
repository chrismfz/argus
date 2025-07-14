package main

import (
	"context"
	"fmt"
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

func printHelp() {
	fmt.Println(`Usage: ./flowenricher [options]

Options:
  -h, --help           Show this help message
  -c, --config FILE    Path to config file (default: auto-detect)
  --debug              Enable debug output
  --show-flows         Print each enriched flow
  --find-path -ip X    Lookup AS path and enrichment for given IP

You can also pass config.yaml as a positional argument.
`)
}

func main() {
	configPath := ""
	var ipToCheck string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "--help", "-h":
			printHelp()
			return
		case "--debug":
			debug = true
		case "--show-flows":
			showFlows = true
		case "--find-path":
			if i+1 < len(os.Args) && os.Args[i+1] == "-ip" && i+2 < len(os.Args) {
				ipToCheck = os.Args[i+2]
				i += 2
			}
		case "--config", "-c":
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			} else {
				log.Fatal("Missing value for --config")
			}
		default:
			if !strings.HasPrefix(arg, "-") && configPath == "" {
				configPath = arg
			}
		}
	}

	if configPath == "" {
		var err error
		configPath, err = getDefaultConfigPath()
		if err != nil {
			log.Fatalf("Error locating default config: %v", err)
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

	if enrichEnabled(cfg, "geoip") {
		geo, err = NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
		if err != nil {
			log.Fatalf("GeoIP init error: %v", err)
		}
	}

	if enrichEnabled(cfg, "bgp") {
		bgp = NewBGPTable(cfg.BGP.TableFile)
	}

	if ipToCheck != "" && bgp != nil {
		path := bgp.FindASPath(ipToCheck)
		if len(path) == 0 {
			fmt.Println("No AS Path found for IP:", ipToCheck)
		} else {
			fmt.Println("AS Path for", ipToCheck, "=>", strings.Join(path, " "))
		}
		return
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
