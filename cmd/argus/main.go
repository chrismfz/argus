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
	"github.com/fsnotify/fsnotify"
        "argus/internal/fields"
        "argus/internal/config"
        "argus/internal/collectors"
        "argus/internal/detection"
        "argus/internal/enrich"
        "argus/internal/api"
        "argus/internal/bgp"
	"argus/internal/cfmapi"
	"database/sql"
	_ "modernc.org/sqlite"
	"argus/internal/sqlite"
	"argus/internal/clickhouse"
	"path/filepath"
	"argus/internal/flow"

)

var debug bool
var myNets []*net.IPNet
var Version   = "dev" // fallback version
var BuildTime = "unknown"



func dlog(msg string, args ...interface{}) {
        if debug {
                log.Printf("[DEBUG] "+msg, args...)
        }
}

func printHelp() {
        fmt.Println(`Usage: ./argus [options]

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







/////////////////// MAIN //////////////////
func main() {
        var configPath string
// subsystem handles (local to main)
	var listener *bgp.BGPListener
	var resolver *enrich.DNSResolver
	var engine *detection.Engine
	var detectionRules []detection.DetectionRule

	//context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handleSignals(cancel)

        // parameters
        for i := 1; i < len(os.Args); i++ {
                arg := os.Args[i]
                switch arg {
                case "--help", "-h":
                        printHelp()
                        return
                case "--version", "-v":
                fmt.Printf("argus version %s (built at %s)\n", Version, BuildTime)
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


fmt.Printf("Starting argus %s (built at %s)\n", Version, BuildTime)

        // load config
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
config.AppConfig = cfg
debug = debug || cfg.Debug


// ==== Print effective ANOMALY config (startup) ====
ac := cfg.Detection.Anomaly
pf := ac.Prefilter
log.Printf("[CFG] anomaly: enabled=%v window=%s interval=%s label=%s min_score=%.3f log_only=%v",
    ac.Enabled, ac.Window, ac.Interval, ac.Label, ac.MinScore, ac.LogOnly)
log.Printf("[CFG] anomaly: retrain_every=%s baseline_max=%d top_k=%d trees=%d sample_size=%d contamination=%.3f",
    ac.RetrainEvery, ac.BaselineMax, ac.TopK, ac.Trees, ac.SampleSize, ac.Contamination)
log.Printf("[CFG] anomaly: require_hbos_percentile=%.3f weights={iforest:%.2f,hbos:%.2f} print_above_mean_percent=%.0f allow_asns=%v",
    ac.RequireHBOSPercentile, ac.Weights.IForest, ac.Weights.HBOS, ac.PrintAboveMeanPercent, ac.AllowASNs)
log.Printf("[CFG] anomaly.prefilter: pps>=%.1f uniq_ports>=%.0f uniq_ips>=%.0f syn_ratio>=%.2f icmp_share>=%.2f",
    pf.MinPPS, pf.MinUniqDstPorts, pf.MinUniqDstIPs, pf.MinSynRatio, pf.MinICMPShare)



// ==== Print effective MEMORY ANOMALY config (startup) ====
mc := cfg.Detection.Memory
log.Printf("[CFG] memory: enabled=%v interval=%s log_path=%s alpha=%.2f theta=%.2f tau_risk=%.2f",
    mc.Enabled, mc.Interval, mc.LogPath, mc.Alpha, mc.Theta, mc.TauRisk)
log.Printf("[CFG] memory: debt(decay=%.2f warn=%.2f) flags(spike=%.2f consec=%d d5m=%.3f d30m=%.3f) ttl=%s top_k_enrich=%d state_changes_only=%v",
    mc.Debt.DecayPerTick, mc.Debt.WarnThreshold, mc.Flags.SpikeThreshold, mc.Flags.ConsecHighWarn,
    mc.Flags.Decay5m, mc.Flags.Decay30m, mc.TTL, mc.TopKEnrich, mc.LogStateChangesOnly)





// ---- CFM client + heartbeat (must be one contiguous if/else block)
var cfm *cfmapi.Client
if cfg.CFM.Enabled && cfg.CFM.URL != "" && cfg.CFM.Token != "" {
    cfm = &cfmapi.Client{
        BaseURL: cfg.CFM.URL,
        Token:   cfg.CFM.Token,
    }
    log.Printf("[CFM] enabled url=%s", cfg.CFM.URL)

    // Send one heartbeat now
    if err := cfm.Heartbeat(ctx, Version, "argus"); err != nil {
        log.Printf("[CFM] heartbeat (startup) failed: %v", err)
    } else {
        log.Printf("[CFM] heartbeat (startup) ok")
    }

    // Then every 30s until shutdown
    go func() {
        t := time.NewTicker(30 * time.Second)
        defer t.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-t.C:
                if err := cfm.Heartbeat(ctx, Version, "argus"); err != nil {
                    log.Printf("[CFM] heartbeat failed: %v", err)
                }
            }
        }
    }()
} else {
    log.Printf("[CFM] disabled or misconfigured (enabled=%v url=%q token_len=%d)",
        cfg.CFM.Enabled, cfg.CFM.URL, len(cfg.CFM.Token))
}




// Initialize clickhouse client for enrichment
if err := clickhouse.Init(*cfg); err != nil {
    log.Fatalf("[FATAL] ClickHouse init failed: %v", err)
}
if err := clickhouse.EnsureTables(); err != nil {
    log.Fatalf("[FATAL] EnsureTables failed: %v", err)
}



// ── SQLite: open with WAL + busy timeout; serialize writers
// NOTE: Using 'file:' DSN to set pragmas at connection open.
dsn := "file:detections.sqlite?mode=rwc" +
       "&_pragma=journal_mode(WAL)" +
       "&_pragma=synchronous(NORMAL)" +
       "&_pragma=busy_timeout(5000)" +
       "&cache=shared"
db, err := sql.Open("sqlite", dsn)
if err != nil {
	log.Fatal("Failed to open DB:", err)
}
defer db.Close()

// Guarantee a single writer connection so we don’t contend inside SQLite.
db.SetMaxOpenConns(1)
db.SetMaxIdleConns(1)
// Optional: no TTL for connections
// db.SetConnMaxLifetime(0)

// Belt-and-suspenders if DSN pragmas ever change:
if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
        log.Printf("[SQLite] set WAL failed: %v", err)
}
_, _ = db.Exec(`PRAGMA synchronous=NORMAL;`)
_, _ = db.Exec(`PRAGMA busy_timeout=5000;`)



if err := sqlite.InitSQLiteSchema(db); err != nil {
	log.Fatal("Failed to init schema:", err)
}

log.Println("✅ SQLite schema initialized")


// Health check: quick no-op to ensure DB is writable after (re)create
if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _healthcheck (k TEXT PRIMARY KEY, v TEXT);`); err != nil {
        log.Fatalf("[SQLite] healthcheck table create failed: %v", err)
}

// 🧹 Auto-clean expired blackholes on startup
if err := detection.CleanupExpiredBlackholes(db); err != nil {
	log.Printf("[WARN] Failed to cleanup expired blackholes: %v", err)
}

// 🕒 Periodic auto-clean every 1 minute
go func() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := detection.CleanupExpiredBlackholes(db); err != nil {
				log.Printf("[WARN] Periodic blackhole cleanup error: %v", err)
			}
		}
	}
}()
// sqlite end





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




        // --- Load & hot-reload protection list (etc/exclude.detections.conf) ---
        protPath := filepath.Join("etc", "exclude.detections.conf")
        if err := detection.LoadProtectedFromFile(protPath); err != nil {
                log.Printf("[SAFEGUARD] protection list not loaded (%s): %v", protPath, err)
        } else {
                log.Printf("[SAFEGUARD] protection list loaded from %s", protPath)
        }
        // fsnotify watcher (reload on change)
        go func() {
                w, err := fsnotify.NewWatcher()
                if err != nil {
                        log.Printf("[SAFEGUARD] fsnotify init failed: %v", err)
                        return
                }
                defer w.Close()
                // It’s OK if Add fails (file may not exist yet); we’ll rely on the timer below.
                _ = w.Add(protPath)
                for {
                        select {
                        case <-ctx.Done():
                                return
                        case ev := <-w.Events:
                                if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
                                        // small debounce
                                        time.Sleep(150 * time.Millisecond)
                                        if err := detection.LoadProtectedFromFile(protPath); err != nil {
                                                log.Printf("[SAFEGUARD] reload failed: %v", err)
                                        } else {
                                                log.Printf("[SAFEGUARD] reloaded protection list (%s)", protPath)
                                        }
                                }
                        case err := <-w.Errors:
                                log.Printf("[SAFEGUARD] fsnotify error: %v", err)
                        }
                }
        }()
        // Fallback: periodic reload every 60s (covers replace/move cases)
        go func() {
                t := time.NewTicker(60 * time.Second)
                defer t.Stop()
                for {
                        select {
                        case <-ctx.Done():
                                return
                        case <-t.C:
                                _ = detection.LoadProtectedFromFile(protPath)
                        }
                }
        }()



        dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
        dlog("enrich.GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
        if cfg.GeoIP.CityDB != "" {
                dlog("enrich.GeoIP City DB: %s", cfg.GeoIP.CityDB)
        }
        if cfg.DNS.Nameserver != "" {
                dlog("Using DNS resolver: %s", cfg.DNS.Nameserver)
        }

        // enrich.GeoIP resolver
        geo := enrichers.Geo


// Start SNMP

var ifNameCache *enrich.IFNameCache
if config.EnrichEnabled(cfg, "snmp") && cfg.SNMP.Enabled {
    fmt.Printf("[INFO] SNMP enrichment is ENABLED (target = %s)\n", cfg.SNMP.Target)
    snmpClient, err := enrich.InitSNMPClient(cfg.SNMP)
    if err != nil {
        log.Printf("[WARN] SNMP connect failed: %v\n", err)
    } else {
        ifNameCache = enrich.NewIFNameCache()
        ifNameCache.StartRefreshLoop(snmpClient, 5*time.Minute)
enrich.SNMPClient = snmpClient
enrich.IFNames = ifNameCache
enrich.StartSNMPStatsCollector() // ✅ ξεκινά το async writer

    }
} else {
    fmt.Println("[INFO] SNMP enrichment is DISABLED")
}




// BGP Listener
if config.EnrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
    listener = bgp.NewBGPListener(cfg.BGP.Listener)
//bgp.SetMyASN(cfg.MyASN) //chris test local ASN
bgp.SetMyASN(cfg.BGP.Listener.ASN)
    if err := listener.Start(); err != nil {
        log.Fatalf("Failed to start BGP listener: %v", err)
    }

bgp.SetAnnounceServer(listener.Server)
//set your next-hop override so handleAnnounce() defaults correctly
bgp.LocalBGPAddress = cfg.BGP.Listener.ListenIP


    fmt.Println("[INFO] Warming up BGP session to collect prefixes...")
	listener.WaitReady(ctx, 100_000, 60*time.Second)
    fmt.Printf("[INFO] BGP warm-up done. Known prefixes: %d\n", listener.PathCount)


//  Restore active blackholes from SQLite into BGP -- AFTER BGP
if config.EnrichEnabled(cfg, "bgp") {
	if err := detection.RestoreActiveBlackholes(db); err != nil {
		log.Printf("[WARN] Failed to restore active blackholes: %v", err)
	}
}


    // 👉 Inject manually your own prefixes into the Ranger
    for _, n := range myNets {
        entry := bgp.BGPEnrichedEntry{
            Net:    *n,
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
if config.EnrichEnabled(cfg, "ptr") {
	log.Println("[INFO] PTR enrichment is ENABLED")
	// start the async PTR resolver
	enrich.StartPTRResolver(cfg, geo, debug)
}




        // ClickHouse Inserter
        inserter := clickhouse.NewInserter(cfg.ClickHouse.Table)
        dlog("ClickHouse connection established.")

        batcher := flow.NewInsertFlowBatcher(
                inserter,
                cfg.Insert.BatchSize,
                time.Duration(cfg.Insert.FlushIntervalMs)*time.Millisecond,
                listener.Ranger,
                ifNameCache,
                cfg.BGP.Listener.StoreASPath,
			geo,
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

                                        flow := flow.ConvertToFlowRecord(raw)
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


//  DetectionStore logic
var store detection.DetectionStore
if db != nil {
	store = detection.NewSQLiteStore(db)
	log.Println("[INFO] Using SQLite-based detection store")
} else {
	store = detection.NewMemoryStore()
	log.Println("[WARN] Falling back to in-memory detection store")
}

// Start detection engine with store
engine = detection.NewEngine(
    detectionRules,
    cfg.MyASN,
    myNets,
    maxWin,
    enrichers.Geo,
    enrichers.DNS,
    store,
)



//Clickhouse case for alert detections //
engine.SetClickHouseWriter(detection.NewClickHouseWriter())

if cfm != nil {
    engine.SetReporter(cfm)
}



// ===== ANOMALY (one-liner: wire + hot-reload inside detection) =====
if cfg.Detection.Enabled && cfg.Detection.Anomaly.Enabled {
        _, _ = detection.StartAnomalyStack(ctx, cfg, engine, store, configPath)
}



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
	api.DB = db
        api.Resolver = resolver
        if listener != nil {
                api.Ranger = listener.Ranger
        }
	api.CFM = cfm
        api.Start()
}()








        <-ctx.Done()
        log.Println("Shutdown complete.")
}
