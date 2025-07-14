package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var debug bool
var showFlows bool
var geo *GeoIP
var listener *BGPListener
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
  --find-path X        Lookup AS path and enrichment for given IP

You can also pass config.yaml as a positional argument.`)
}

func main() {
	var configPath string
	var findPathMode bool
	var findPathIP string

	// First pass: detect if --find-path mode is requested
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--find-path" && i+1 < len(os.Args) {
			findPathMode = true
			findPathIP = os.Args[i+1]
			break
		}
	}

	// If --find-path mode, only load config and start BGP
	if findPathMode {
configPath, err := getDefaultConfigPath()
if err != nil {
    log.Fatalf("Error locating default config: %v", err)
}
cfg, err := LoadConfig(configPath)
if err != nil {
    log.Fatalf("Error loading config: %v", err)
}
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}

		if enrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
			listener = NewBGPListener(cfg.BGP.Listener)
			if err := listener.Start(); err != nil {
				log.Fatalf("Failed to start BGP listener: %v", err)
			}
		}

		fmt.Println("Waiting for BGP prefixes to load (min 700k)...")
		for i := 0; i < 30; i++ { // max 30s
			if listener.PathCount >= 700000 {
				break
			}
			fmt.Printf("Loaded: %d prefixes\r", listener.PathCount)
			time.Sleep(1 * time.Second)
		}
		fmt.Printf("Prefixes loaded: %d\n", listener.PathCount)
		findASPath(findPathIP)
		return
	}

	// Normal mode
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

	if enrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
		listener = NewBGPListener(cfg.BGP.Listener)
		if err := listener.Start(); err != nil {
			log.Fatalf("Failed to start BGP listener: %v", err)
		}
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
		listener.Ranger,
	)
	defer batcher.Close()

	err = StartKafkaConsumer(ctx, cfg, geo, listener.Ranger, resolver, batcher)
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

func findASPath(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP: %s", ipStr)
	}

	if listener == nil || listener.Ranger == nil {
		log.Fatal("BGP listener or Ranger not initialized")
	}

	entries, err := listener.Ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		fmt.Printf("No BGP entry found for %s\n", ip)
		return
	}

	for _, e := range entries {
		if entry, ok := e.(BGPEnrichedEntry); ok {
			fmt.Printf("Matched Prefix: %s\n", entry.network.String())
			fmt.Printf("AS Path: %v\n", entry.ASPath)
			fmt.Printf("Local Pref: %d\n", entry.LocalPref)
		}
	}
}
