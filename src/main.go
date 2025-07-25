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
        "flowenricher/config"
        "flowenricher/collectors"
	"flowenricher/detection"
)

var debug bool
var geo *GeoIP
var listener *BGPListener
var resolver *DNSResolver
var myNets []*net.IPNet
var Version   = "dev" // fallback version
var BuildTime = "unknown"
var engine *detection.Engine


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
  -v, --version	       Show version (sic)

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
	dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
	if cfg.GeoIP.CityDB != "" {
		dlog("GeoIP City DB: %s", cfg.GeoIP.CityDB)
	}
	if cfg.DNS.Nameserver != "" {
		dlog("Using DNS resolver: %s", cfg.DNS.Nameserver)
	}

	// GeoIP resolver
	if enrichEnabled(cfg, "geoip") {
		geo, err = NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB)
		if err != nil {
			log.Fatalf("GeoIP init error: %v", err)
		}
	}



// Start SNMP

// Start SNMP

var ifNameCache *IFNameCache
if enrichEnabled(cfg, "snmp") && cfg.SNMP.Enabled {
    fmt.Printf("[INFO] SNMP enrichment is ENABLED (target = %s)\n", cfg.SNMP.Target)
    snmpClient, err := InitSNMPClient(cfg.SNMP)
    if err != nil {
        log.Printf("[WARN] SNMP connect failed: %v\n", err)
    } else {
        ifNameCache = NewIFNameCache()
        ifNameCache.StartRefreshLoop(snmpClient, 5*time.Minute)
    }
} else {
    fmt.Println("[INFO] SNMP enrichment is DISABLED")
}




// BGP Listener
if enrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
    listener = NewBGPListener(cfg.BGP.Listener)
    if err := listener.Start(); err != nil {
        log.Fatalf("Failed to start BGP listener: %v", err)
    }

    fmt.Println("[INFO] Warming up BGP session to collect prefixes...")
    time.Sleep(30 * time.Second)
    fmt.Printf("[INFO] BGP warm-up done. Known prefixes: %d\n", listener.PathCount)

    // 👉 Inject manually your own prefixes into the Ranger
    for _, n := range myNets {
        entry := BGPEnrichedEntry{
            Net:    *n,
            ASN:    cfg.MyASN,
            ASPath: []string{fmt.Sprintf("%d", cfg.MyASN)},
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
		//resolver = NewDNSResolver(cfg.DNS.Nameserver) // old slow way
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
					flow := ConvertToFlowRecord(raw)
					batcher.Add(flow)

if engine != nil {
    engine.AddFlow(detection.Flow{
        Timestamp: flow.TimestampStart,
        SrcIP:     flow.SrcHost,
        DstIP:     flow.DstHost,
        SrcPort:   flow.SrcPort,
        DstPort:   flow.DstPort,
        Proto:     detection.ProtocolToString(flow.Proto),
        TCPFlags:  flow.TCPFlags,
        Packets:   flow.Packets,
        Bytes:     flow.Bytes,
    })
}

					counter++
					if counter%100000 == 0 {
						log.Printf("[NETFLOW] Processed %d flows", counter)
					}
				}
			}(netflow)
		} else {
			log.Println("Skipping collector without FlowChannel or incorrect type")
		}
	}





// Detection Engine //
var detectionRules []detection.DetectionRule

if cfg.Detection.Enabled {
    fmt.Println("[INFO] Detection engine is ENABLED")
    detectionRules, err = detection.LoadDetectionRules(cfg.Detection.RulesConfig)
    if err != nil {
        log.Fatalf("Failed to load detection rules: %v", err)
    }
    fmt.Printf("[INFO] Loaded %d detection rules\n", len(detectionRules))

    // 👉 Ανάγνωση flow_cache_max_window από config
    maxWin := 10 * time.Second // προεπιλογή
    if cfg.Detection.FlowCacheMaxWindow != "" {
        if d, err := time.ParseDuration(cfg.Detection.FlowCacheMaxWindow); err == nil {
            maxWin = d
        } else {
            log.Printf("[WARN] Invalid flow_cache_max_window: %v", err)
        }
    }

    // 👉 Εκκίνηση detection engine με παραμέτρους
    engine := detection.NewEngine(
        detectionRules,
        geo,
        resolver,
        ifNameCache,
        cfg.MyASN,
        myNets,
        maxWin,
    )

    go engine.Run(ctx)
} else {
    fmt.Println("[INFO] Detection engine is DISABLED")
}







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




// Μπορείς να προσθέσεις αυτό στο main() για δοκιμή
go func() {
    time.Sleep(5 * time.Second)
    detection.LogDetection(
        detection.DetectionRule{
            Name: "manual_test",
            Proto: "tcp",
            DstPort: 80,
            TimeWindow: "5s",
            Action: "alert",
        },
        []detection.Flow{
            {
                SrcIP: "1.2.3.4",
                DstIP: "5.6.7.8",
                Proto: "tcp",
                SrcPort: 12345,
                DstPort: 80,
                Timestamp: time.Now(),
                Packets: 10,
                Bytes: 1000,
            },
        },
        geo,
        resolver,
    )
}()




	<-ctx.Done()
	log.Println("Shutdown complete.")
}

