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
        "flowenricher/fields"
        "flowenricher/config"
        "flowenricher/collectors"
        "flowenricher/detection"
        "flowenricher/enrich"
        "flowenricher/api"
        "flowenricher/bgp"



)

var debug bool
var geo *enrich.GeoIP
var listener *bgp.BGPListener
var resolver *enrich.DNSResolver
var myNets []*net.IPNet
var Version   = "dev" // fallback version
var BuildTime = "unknown"
var engine *detection.Engine
var detectionRules []detection.DetectionRule // MOVED THIS DECLARATION TO GLOBAL SCOPE


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
  -v, --version        Show version (sic)

You can also pass config.yaml as a positional argument.`)
}

func handleSignals(cancel context.CancelFunc) {
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
        <-sigChan
        log.Println("Interrupt received, exiting gracefully...")
        cancel()
}

func enrichEnabled(cfg *config.Config, name string) bool {
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






/////////////////// MAIN //////////////////
func main() {
        var configPath string

        // Επεξεργασία παραμέτρων
        for i := 1; i < len(os.Args); i++ {
                arg := os.Args[i]
                switch arg {
                case "--help", "-h":
                        printHelp()
                        return
                case "--version", "-v":
                fmt.Printf("flowenricher version %s (built at %s)\n", Version, BuildTime)
                return
                case "--debug":
                        debug = true
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


fmt.Printf("Starting flowenricher %s (built at %s)\n", Version, BuildTime)

        // Φόρτωση config
        if configPath == "" {
                var err error
                configPath, err = config.GetDefaultConfigPath()
                if err != nil {
                        log.Fatalf("Error locating default config: %v", err)
                }
        }
        cfg, err := config.LoadConfig(configPath)
        if err != nil {
                log.Fatalf("Error loading config: %v", err)
        }
        debug = debug || cfg.Debug

enrichers, err := enrich.Init(cfg)
if err != nil {
	log.Fatalf("Failed to initialize enrichment modules: %v", err)
}


for _, s := range cfg.MyPrefixes {
    _, n, err := net.ParseCIDR(s)
    if err == nil {
        myNets = append(myNets, n)
    } else {
        log.Printf("[WARN] Invalid CIDR in my_prefixes: %s", s)
    }
}


fmt.Printf("[INFO] Loaded MyASN = %d\n", cfg.MyASN)
fmt.Printf("[INFO] Loaded %d local prefixes:\n", len(myNets))
for _, n := range myNets {
    fmt.Printf("  - %s\n", n.String())
}




        dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
        dlog("enrich.GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
        if cfg.GeoIP.CityDB != "" {
                dlog("enrich.GeoIP City DB: %s", cfg.GeoIP.CityDB)
        }
        if cfg.DNS.Nameserver != "" {
                dlog("Using DNS resolver: %s", cfg.DNS.Nameserver)
        }

        // enrich.GeoIP resolver
        if enrichEnabled(cfg, "geoip") {
                geo, err = enrich.NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
                if err != nil {
                        log.Fatalf("enrich.GeoIP init error: %v", err)
                }
        }



// Start SNMP

var ifNameCache *enrich.IFNameCache
if enrichEnabled(cfg, "snmp") && cfg.SNMP.Enabled {
    fmt.Printf("[INFO] SNMP enrichment is ENABLED (target = %s)\n", cfg.SNMP.Target)
    snmpClient, err := enrich.InitSNMPClient(cfg.SNMP)
    if err != nil {
        log.Printf("[WARN] SNMP connect failed: %v\n", err)
    } else {
        ifNameCache = enrich.NewIFNameCache()
        ifNameCache.StartRefreshLoop(snmpClient, 5*time.Minute)
    }
} else {
    fmt.Println("[INFO] SNMP enrichment is DISABLED")
}




// BGP Listener
if enrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
    listener = bgp.NewBGPListener(cfg.BGP.Listener)
bgp.SetMyASN(cfg.MyASN)
    if err := listener.Start(); err != nil {
        log.Fatalf("Failed to start BGP listener: %v", err)
    }

bgp.SetAnnounceServer(listener.Server)
//set your next-hop override so handleAnnounce() defaults correctly
bgp.LocalBGPAddress = cfg.BGP.Listener.ListenIP


    fmt.Println("[INFO] Warming up BGP session to collect prefixes...")
    time.Sleep(30 * time.Second)
    fmt.Printf("[INFO] BGP warm-up done. Known prefixes: %d\n", listener.PathCount)

    // 👉 Inject manually your own prefixes into the Ranger
    for _, n := range myNets {
        entry := bgp.BGPEnrichedEntry{
            Net:    *n,
            ASN:    cfg.MyASN,
            ASPath: []string{fmt.Sprintf("%d", cfg.MyASN)},
	    //Communities: communities,
        }
        if err := listener.Ranger.Insert(entry); err != nil {
            log.Printf("[WARN] Failed to insert local prefix %s: %v", n.String(), err)
        } else {
            log.Printf("[INFO] Inserted local prefix %s into BGP Ranger (ASN %d)", n.String(), cfg.MyASN)
        }
    }
}



        // PTR Resolver
        if enrichEnabled(cfg, "ptr") {
                //resolver = enrich.NewDNSResolver(cfg.DNS.Nameserver) // old slow way
                StartPTRResolver(cfg) // async clickhouse queries
        }

        // ClickHouse Inserter
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
        cfg.MyASN,
        myNets, // my IPs and my ASN
            ifNameCache, // interface names
        )

        defer batcher.Close()


// NetFlow Collectors
        fmt.Println("Starting Netflow Collectors...")
        flowCollectors := cfg.GetCollectors()

        if len(flowCollectors) == 0 {
                fmt.Println("No Netflow Collectors configured in config.yml. Skipping collector startup.")
        } else {
                for _, f := range flowCollectors {
                        go f.Start()
                        fmt.Printf("Started collector: %+v\n", f)
                }
                fmt.Printf("[ OK ] Netflow Collectors started.\n")
        }

        // Reader από FlowChannel κάθε συλλέκτη
        for _, f := range flowCollectors {
                if netflow, ok := f.(*collectors.Netflow); ok && netflow.FlowChannel != nil {
                        go func(n *collectors.Netflow) {
                                counter := 0
                                for raw := range n.FlowChannel {
                                        dlog("Received raw flow from collector. Raw data (first few fields): Proto=%v, SrcIP=%v, DstIP=%v",
                                                raw[fields.PROTOCOL], raw[fields.IPV4_SRC_ADDR], raw[fields.IPV4_DST_ADDR])

                                        flow := ConvertToFlowRecord(raw)
                                        batcher.Add(flow)

                                        if engine != nil {
                                                flowToAdd := detection.Flow{
                                                        Timestamp: flow.TimestampEnd,
                                                        SrcIP:     flow.SrcHost,
                                                        DstIP:     flow.DstHost,
                                                        SrcPort:   flow.SrcPort,
                                                        DstPort:   flow.DstPort,
                                                        Proto:     detection.ProtocolToString(flow.Proto),
                                                        TCPFlags:  flow.TCPFlags,
                                                        Packets:   flow.Packets,
                                                        Bytes:     flow.Bytes,
                                                }
                                                engine.AddFlow(flowToAdd)
dlog("Extracted timestamp for flow: %s", flowToAdd.Timestamp.Format(time.RFC3339Nano))
                                                dlog("Added flow to detection engine: SrcIP=%s, DstIP=%s, DstPort=%d, Proto=%s, Packets=%d, Timestamp=%s",
                                                        flowToAdd.SrcIP, flowToAdd.DstIP, flowToAdd.DstPort, flowToAdd.Proto, flowToAdd.Packets, flowToAdd.Timestamp.Format(time.RFC3339Nano))
                                        } else {
                                                log.Println("[WARN] Detection engine is nil, cannot add flow.")
                                        }

                                        counter++
                                        if counter%10000 == 0 { // Changed to 1000 for more frequent updates during debug
                                                log.Printf("[NETFLOW] Processed %d flows", counter)
                                        }
                                }
                        }(netflow)
                } else {
                        log.Println("Skipping collector without FlowChannel or incorrect type")
                }
        }


        // Detection Engine //



if cfg.Detection.Enabled {
	// ✅ Ενεργοποίησε detection debugging αν ζητήθηκε
	detection.InitDebugDetection(cfg.Detection.DebugDetection)
	dlog("== Detection debug log initialized ==")

                fmt.Println("[INFO] Detection engine is ENABLED")
                detectionRules, err = detection.LoadDetectionRules(cfg.Detection.RulesConfig)
                if err != nil {
                        log.Fatalf("Failed to load detection rules: %v", err)
                }
                fmt.Printf("[INFO] Loaded %d detection rules\n", len(detectionRules))

                maxWin := 10 * time.Second // default
                if cfg.Detection.FlowCacheMaxWindow != "" {
                        if d, err := time.ParseDuration(cfg.Detection.FlowCacheMaxWindow); err == nil {
                                maxWin = d
                        } else {
                                log.Printf("[WARN] Invalid flow_cache_max_window: %v", err)
                        }
                }

                engine = detection.NewEngine(
                        detectionRules,
                        cfg.MyASN,
                        myNets,
                        maxWin,
			enrichers.Geo,
			enrichers.DNS,
                )

                go engine.Run(ctx)
                dlog("Detection engine started with maxWindow: %s", maxWin.String())
        } else {
                fmt.Println("[INFO] Detection engine is DISABLED")
        }






// START API - make sure it's the last one
// εκκίνηση REST API
if resolver == nil && cfg.DNS.Nameserver != "" {
	resolver = enrich.NewDNSResolver(cfg.DNS.Nameserver)
}


go func() {
        api.Geo = geo
        api.Resolver = resolver
        if listener != nil {
                api.Ranger = listener.Ranger
        }
        api.Start()
}()






// Kafka
if cfg.Kafka.Enabled {
    go func() {
        err := StartKafkaConsumer(ctx, cfg, geo, listener.Ranger, resolver, batcher)
        if err != nil {
            log.Fatalf("Kafka consumer error: %v", err)
        }
    }()
} else {
    log.Println("[INFO] Kafka is disabled in config.yaml, skipping consumer.")
}






        <-ctx.Done()
        log.Println("Shutdown complete.")
}
