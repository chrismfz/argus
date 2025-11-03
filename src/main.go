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
        "flowenricher/fields"
        "flowenricher/config"
        "flowenricher/collectors"
        "flowenricher/detection"
        "flowenricher/enrich"
        "flowenricher/api"
        "flowenricher/bgp"
	"flowenricher/internal/cfmapi"
	"database/sql"
	_ "modernc.org/sqlite"
	"flowenricher/internal/sqlite"
	"flowenricher/clickhouse"
	"path/filepath"

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
// anomaly globals for hot-reload
var anom *detection.Anomaly
// memory lane
var mem *detection.MemoryLayer

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
    if err := cfm.Heartbeat(ctx, Version, "flowenricher"); err != nil {
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
                if err := cfm.Heartbeat(ctx, Version, "flowenricher"); err != nil {
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



// sqlite load
db, err := sql.Open("sqlite", "detections.sqlite")
if err != nil {
	log.Fatal("Failed to open DB:", err)
}
defer db.Close()

if err := sqlite.InitSQLiteSchema(db); err != nil {
	log.Fatal("Failed to init schema:", err)
}

log.Println("✅ SQLite schema initialized")


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




        // --- Load protection list (exclude.detections.conf) ---
        // Prefer local ./etc/ path next to the binary or working dir.
        // Example layout: /opt/flowenricher/etc/exclude.detections.conf
        protPath := filepath.Join("etc", "exclude.detections.conf")
        if err := detection.LoadProtectedFromFile(protPath); err != nil {
                log.Printf("[SAFEGUARD] protection list not loaded (%s): %v", protPath, err)
        } else {
                log.Printf("[SAFEGUARD] protection list loaded from %s", protPath)
        }
        // Optional: periodic reload (every 60s)
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
enrich.SNMPClient = snmpClient
enrich.IFNames = ifNameCache
StartSNMPStatsCollector() // ✅ ξεκινά το async writer

    }
} else {
    fmt.Println("[INFO] SNMP enrichment is DISABLED")
}




// BGP Listener
if enrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
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
    time.Sleep(45 * time.Second)
    fmt.Printf("[INFO] BGP warm-up done. Known prefixes: %d\n", listener.PathCount)


//  Restore active blackholes from SQLite into BGP -- AFTER BGP
if enrichEnabled(cfg, "bgp") {
	if err := detection.RestoreActiveBlackholes(db); err != nil {
		log.Printf("[WARN] Failed to restore active blackholes: %v", err)
	}
}


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
	log.Println("[INFO] PTR enrichment is ENABLED")
	// start the async PTR resolver
	StartPTRResolver(cfg)
}




        // ClickHouse Inserter
        inserter, err := NewClickHouseInserter(cfg)
        if err != nil {
                log.Fatalf("ClickHouse connection error: %v", err)
        }
        dlog("ClickHouse connection established.")

        batcher := NewInsertFlowBatcher(
        inserter,
        cfg.Insert.BatchSize,
        time.Duration(cfg.Insert.FlushIntervalMs)*time.Millisecond,
        listener.Ranger,
        cfg.MyASN,
        myNets,
        ifNameCache,
	cfg.BGP.StoreASPath,
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



/* =====  ANOMALY (config-driven + hot-reload) ===== */
if cfg.Detection.Enabled && cfg.Detection.Anomaly.Enabled {

        // --- Build Memory layer (EWMA + risk counters) ---
        if cfg.Detection.Memory.Enabled {
                mivl, _ := time.ParseDuration(cfg.Detection.Memory.Interval)
                mttl, _ := time.ParseDuration(cfg.Detection.Memory.TTL)
                memCfg := detection.MemoryConfig{
                        Interval:          mivl,
                        Alpha:             cfg.Detection.Memory.Alpha,
                        Theta:             cfg.Detection.Memory.Theta,
                        TauRisk:           cfg.Detection.Memory.TauRisk,
                        DebtDecayPerTick:  cfg.Detection.Memory.Debt.DecayPerTick,
                        DebtWarn:          cfg.Detection.Memory.Debt.WarnThreshold,
                        SpikeThreshold:    cfg.Detection.Memory.Flags.SpikeThreshold,
                        Decay5m:           cfg.Detection.Memory.Flags.Decay5m,
                        Decay30m:          cfg.Detection.Memory.Flags.Decay30m,
                        ConsecHighWarn:    cfg.Detection.Memory.Flags.ConsecHighWarn,
                        TTL:               mttl,
                        LogPath:           cfg.Detection.Memory.LogPath,
                        TopKEnrich:        cfg.Detection.Memory.TopKEnrich,
                        LogStateChangesOnly: cfg.Detection.Memory.LogStateChangesOnly,
                }
                mem = detection.NewMemoryLayer(memCfg)
                mem.StartGC(ctx)
        }

        // Parse durations from YAML
        win, _  := time.ParseDuration(cfg.Detection.Anomaly.Window)
        ivl, _  := time.ParseDuration(cfg.Detection.Anomaly.Interval)
        retr, _ := time.ParseDuration(cfg.Detection.Anomaly.RetrainEvery)

        // Build initial config from file
        anomCfg := detection.AnomalyConfig{
                Window:       win,
                Interval:     ivl,
                Label:        cfg.Detection.Anomaly.Label,
                MinScore:     cfg.Detection.Anomaly.MinScore,
                LogOnly:      cfg.Detection.Anomaly.LogOnly,
		Debug:        cfg.Detection.Anomaly.Debug,
                RetrainEvery: retr,
                BaselineMax:  cfg.Detection.Anomaly.BaselineMax,
		TopK:         cfg.Detection.Anomaly.TopK,
        }

        // Detector hyperparams from file
        trees         := cfg.Detection.Anomaly.Trees
        sampleSize    := cfg.Detection.Anomaly.SampleSize
        contamination := cfg.Detection.Anomaly.Contamination
        if trees <= 0 { trees = 100 }
        if sampleSize <= 0 { sampleSize = 256 }
        if contamination <= 0 { contamination = 0.01 }

        // Create & wire anomaly lane
        det := detection.NewIForestDetector(trees, sampleSize, contamination)
        anom = detection.NewAnomaly(anomCfg, det, store)
        engine.SetAnomaly(anom)



        // Wire existing, single MemoryLayer (if enabled) to anomaly
        if mem != nil {
                anom.SetMemory(mem)
        }

        anom.Start(ctx)

        // --- Hot reload: watch config.yaml (and optionally rules) ---
        go func() {
                watcher, err := fsnotify.NewWatcher()
                if err != nil {
                        log.Printf("[WARN] fsnotify init failed: %v", err)
                        return
                }
                defer watcher.Close()

                if err := watcher.Add(configPath); err != nil {
                        log.Printf("[WARN] fsnotify add failed: %v", err)
                        return
                }
                // also watch rules file so you can reload rules later if you add engine.UpdateRules(...)
                if cfg.Detection.RulesConfig != "" {
                        _ = watcher.Add(cfg.Detection.RulesConfig)
                }

                for {
                        select {
                        case <-ctx.Done():
                                return
                        case ev := <-watcher.Events:
                                if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
                                        continue
                                }
                                // debounce a bit
                                time.Sleep(200 * time.Millisecond)

                                // Reload config
                                nc, err := config.LoadConfig(configPath)
                                if err != nil {
                                        log.Printf("[WARN] reload config failed: %v", err)
                                        continue
                                }
                                config.AppConfig = nc

                                if nc.Detection.Enabled && nc.Detection.Anomaly.Enabled {
                                        // parse durations
                                        nwin, _  := time.ParseDuration(nc.Detection.Anomaly.Window)
                                        nivl, _  := time.ParseDuration(nc.Detection.Anomaly.Interval)
                                        nretr, _ := time.ParseDuration(nc.Detection.Anomaly.RetrainEvery)

                                        newAnom := detection.AnomalyConfig{
                                                Window:       nwin,
                                                Interval:     nivl,
                                                Label:        nc.Detection.Anomaly.Label,
                                                MinScore:     nc.Detection.Anomaly.MinScore,
                                                LogOnly:      nc.Detection.Anomaly.LogOnly,
						Debug:        nc.Detection.Anomaly.Debug,
                                                RetrainEvery: nretr,
                                                BaselineMax:  nc.Detection.Anomaly.BaselineMax,
						TopK:         nc.Detection.Anomaly.TopK,
                                        }
                                        // Live-apply config (requires Anomaly.UpdateConfig)
                                        if anom != nil {
                                                anom.UpdateConfig(newAnom)
                                        }

                                        // If detector params changed, rebuild detector live (requires Anomaly.RebuildDetector)
                                        nTrees := nc.Detection.Anomaly.Trees
                                        nSample := nc.Detection.Anomaly.SampleSize
                                        nContam := nc.Detection.Anomaly.Contamination
                                        if nTrees <= 0 { nTrees = 100 }
                                        if nSample <= 0 { nSample = 256 }
                                        if nContam <= 0 { nContam = 0.01 }
                                        if (nTrees != trees) || (nSample != sampleSize) || (nContam != contamination) {
                                                if anom != nil {
                                                        anom.RebuildDetector(nTrees, nSample, nContam)
                                                }
                                                trees, sampleSize, contamination = nTrees, nSample, nContam
                                                log.Printf("[ANOMALY] detector rebuilt (trees=%d sample=%d contam=%.3f)", trees, sampleSize, contamination)
                                        }

                                        log.Printf("[ANOMALY] reloaded cfg: window=%s interval=%s min_score=%.2f log_only=%v",
                                                newAnom.Window, newAnom.Interval, newAnom.MinScore, newAnom.LogOnly)
                                }



                        // Optional: hot-reload memory layer (simple replace; loses in-RAM state by design)
                        if nc.Detection.Memory.Enabled {
                                nmivl, _ := time.ParseDuration(nc.Detection.Memory.Interval)
                                nmttl, _ := time.ParseDuration(nc.Detection.Memory.TTL)
                                nmemCfg := detection.MemoryConfig{
                                        Interval:            nmivl,
                                        Alpha:               nc.Detection.Memory.Alpha,
                                        Theta:               nc.Detection.Memory.Theta,
                                        TauRisk:             nc.Detection.Memory.TauRisk,
                                        DebtDecayPerTick:    nc.Detection.Memory.Debt.DecayPerTick,
                                        DebtWarn:            nc.Detection.Memory.Debt.WarnThreshold,
                                        SpikeThreshold:      nc.Detection.Memory.Flags.SpikeThreshold,
                                        Decay5m:             nc.Detection.Memory.Flags.Decay5m,
                                        Decay30m:            nc.Detection.Memory.Flags.Decay30m,
                                        ConsecHighWarn:      nc.Detection.Memory.Flags.ConsecHighWarn,
                                        TTL:                 nmttl,
                                        LogPath:             nc.Detection.Memory.LogPath,
                                        TopKEnrich:          nc.Detection.Memory.TopKEnrich,
                                        LogStateChangesOnly: nc.Detection.Memory.LogStateChangesOnly,
                                }

                                mem = detection.NewMemoryLayer(nmemCfg)
                                mem.StartGC(ctx)
                                if anom != nil { anom.SetMemory(mem) }
                                log.Printf("[MEMORY] reloaded cfg: interval=%s alpha=%.2f theta=%.2f tau=%.2f",
                                        nmemCfg.Interval, nmemCfg.Alpha, nmemCfg.Theta, nmemCfg.TauRisk)
                        }

                                // TODO (optional): if ev.Name == cfg.Detection.RulesConfig => reload rules & engine.UpdateRules(...)

                        case err := <-watcher.Errors:
                                log.Printf("[WARN] fsnotify error: %v", err)
                        }
                }
        }()
}
 /* ===== END ANOMALY ===== */





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
