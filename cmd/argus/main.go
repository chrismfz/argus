package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"


	"argus/internal/maxmind"
	_ "modernc.org/sqlite"
	"github.com/fsnotify/fsnotify"

	"argus/internal/api"
	"argus/internal/bgp"
	"argus/internal/cfmapi"
	"argus/internal/clickhouse"
	"argus/internal/collectors"
	"argus/internal/config"
	"argus/internal/detection"
	"argus/internal/enrich"
	"argus/internal/fields"
	"argus/internal/flow"
	"argus/internal/sqlite"
	"argus/internal/telemetry"
)

var debug bool
var Version   = "dev"
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
  -v, --version        Show version`)
}

func handleSignals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	log.Println("Interrupt received, exiting gracefully...")
	cancel()
}

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	var (
		configPath     string
		listener       *bgp.BGPListener
		engine         *detection.Engine
		detectionRules []detection.DetectionRule
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel)

	// ── CLI flags ─────────────────────────────────────────────────────────────
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
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
			if !strings.HasPrefix(os.Args[i], "-") && configPath == "" {
				configPath = os.Args[i]
			}
		}
	}

	fmt.Printf("Starting argus %s (built at %s)\n", Version, BuildTime)

	// ── Config ────────────────────────────────────────────────────────────────
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
	config.LogStartup(cfg)

	// ── CFM client ────────────────────────────────────────────────────────────
	var cfm *cfmapi.Client
	if cfg.CFM.Enabled && cfg.CFM.URL != "" && cfg.CFM.Token != "" {
		cfm = &cfmapi.Client{BaseURL: cfg.CFM.URL, Token: cfg.CFM.Token}
		log.Printf("[CFM] enabled url=%s", cfg.CFM.URL)
		if err := cfm.Heartbeat(ctx, Version, "argus"); err != nil {
			log.Printf("[CFM] heartbeat (startup) failed: %v", err)
		} else {
			log.Printf("[CFM] heartbeat (startup) ok")
		}
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

	// ── ClickHouse ────────────────────────────────────────────────────────────
	if err := clickhouse.Init(*cfg); err != nil {
		log.Fatalf("[FATAL] ClickHouse init failed: %v", err)
	}
	if err := clickhouse.EnsureTables(); err != nil {
		log.Fatalf("[FATAL] EnsureTables failed: %v", err)
	}

	// ── SQLite ────────────────────────────────────────────────────────────────
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
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		log.Printf("[SQLite] set WAL failed: %v", err)
	}
	_, _ = db.Exec(`PRAGMA synchronous=NORMAL;`)
	_, _ = db.Exec(`PRAGMA busy_timeout=5000;`)
	if err := sqlite.InitSQLiteSchema(db); err != nil {
		log.Fatal("Failed to init schema:", err)
	}
	log.Println("[SQLite] schema initialized")
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _healthcheck (k TEXT PRIMARY KEY, v TEXT);`); err != nil {
		log.Fatalf("[SQLite] healthcheck table create failed: %v", err)
	}
	if err := detection.CleanupExpiredBlackholes(db); err != nil {
		log.Printf("[WARN] Failed to cleanup expired blackholes: %v", err)
	}
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := detection.CleanupExpiredBlackholes(db); err != nil {
					log.Printf("[WARN] Periodic blackhole cleanup error: %v", err)
				}
			}
		}
	}()


	// ── MaxMind preflight ─────────────────────────────────────────────────────
	// Block until all .mmdb files exist. Downloads only what is missing.
	if cfg.MaxMind.Enabled {
		log.Printf("[maxmind] checking db files in %s ...", cfg.MaxMind.DBPath)
		if err := maxmind.EnsureDBs(maxmind.Config{
			AccountID:   cfg.MaxMind.AccountID,
			LicenseKey:  cfg.MaxMind.LicenseKey,
			Editions:    cfg.MaxMind.Editions,
			Dir:         cfg.MaxMind.DBPath,
			HTTPTimeout: cfg.MaxMind.HTTPTimeout,
		}); err != nil {
			log.Fatalf("[maxmind] preflight failed: %v", err)
		}
		log.Printf("[maxmind] db files ok")
	}

	// ── MaxMind background updater ────────────────────────────────────────────
	mmLifecycle := maxmind.NewLifecycle()
	mmLifecycle.ApplyConfig(ctx, &cfg.MaxMind)
	defer mmLifecycle.Stop()



	// ── Enrichment ────────────────────────────────────────────────────────────
	enrichers, err := enrich.Init(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize enrichment modules: %v", err)
	}
	geo      := enrichers.Geo
	resolver := enrichers.DNS

	// ── My prefixes ───────────────────────────────────────────────────────────
	var myNets []*net.IPNet
	for _, s := range cfg.MyPrefixes {
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			myNets = append(myNets, n)
		} else {
			log.Printf("[WARN] Invalid CIDR in my_prefixes: %s", s)
		}
	}
	log.Printf("[INFO] MyASN=%d, local prefixes=%d", cfg.MyASN, len(myNets))
	for _, n := range myNets {
		log.Printf("[INFO]   %s", n.String())
	}

	// ── Telemetry ─────────────────────────────────────────────────────────────
	// Must be after myNets is built (Init needs it) and after SQLite is ready.
	if err := telemetry.InitSchema(db); err != nil {
		log.Printf("[telemetry] schema init failed: %v", err)
	}
	telemetry.Init(uint32(cfg.MyASN), myNets)
	telemetry.StartScheduler(ctx, db)
	log.Printf("[telemetry] aggregator ready (myASN=%d nets=%d)", cfg.MyASN, len(myNets))

	// ── Protection list ───────────────────────────────────────────────────────
	protPath := filepath.Join("etc", "exclude.detections.conf")
	if err := detection.LoadProtectedFromFile(protPath); err != nil {
		log.Printf("[SAFEGUARD] protection list not loaded (%s): %v", protPath, err)
	} else {
		log.Printf("[SAFEGUARD] protection list loaded from %s", protPath)
	}
	go func() {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			log.Printf("[SAFEGUARD] fsnotify init failed: %v", err)
			return
		}
		defer w.Close()
		_ = w.Add(protPath)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-w.Events:
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
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
	dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)

	// ── SNMP ──────────────────────────────────────────────────────────────────
	var ifNameCache *enrich.IFNameCache
	if config.EnrichEnabled(cfg, "snmp") && cfg.SNMP.Enabled {
		log.Printf("[INFO] SNMP enrichment enabled (target=%s)", cfg.SNMP.Target)
		snmpClient, err := enrich.InitSNMPClient(cfg.SNMP)
		if err != nil {
			log.Printf("[WARN] SNMP connect failed: %v", err)
		} else {
			ifNameCache = enrich.NewIFNameCache()
			ifNameCache.StartRefreshLoop(snmpClient, 5*time.Minute)
			enrich.SNMPClient = snmpClient
			enrich.IFNames = ifNameCache
			enrich.StartSNMPStatsCollector()
		}
	} else {
		log.Printf("[INFO] SNMP enrichment disabled")
	}

	// ── BGP ───────────────────────────────────────────────────────────────────
	if config.EnrichEnabled(cfg, "bgp") && cfg.BGP.Listener.Enabled {
		listener = bgp.NewBGPListener(cfg.BGP.Listener)
		bgp.SetMyASN(cfg.BGP.Listener.ASN)
		if err := listener.Start(); err != nil {
			log.Fatalf("Failed to start BGP listener: %v", err)
		}
		bgp.SetAnnounceServer(listener.Server)
		bgp.LocalBGPAddress = cfg.BGP.Listener.ListenIP

		log.Print("[INFO] Warming up BGP session...")
		listener.WaitReady(ctx, 100_000, 60*time.Second)
		log.Printf("[INFO] BGP warm-up done. Known prefixes: %d", listener.PathCount)

		if err := detection.RestoreActiveBlackholes(db); err != nil {
			log.Printf("[WARN] Failed to restore active blackholes: %v", err)
		}

		for _, n := range myNets {
			entry := bgp.BGPEnrichedEntry{
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

	// ── PTR resolver ──────────────────────────────────────────────────────────
	if config.EnrichEnabled(cfg, "ptr") {
		log.Println("[INFO] PTR enrichment enabled")
		enrich.StartPTRResolver(cfg, geo, debug)
	}

	// ── Flow pipeline ─────────────────────────────────────────────────────────
	inserter := clickhouse.NewInserter(cfg.ClickHouse.Table)
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

	log.Print("[INFO] Starting NetFlow collectors...")
	flowCollectors := cfg.GetCollectors()
	if len(flowCollectors) == 0 {
		log.Print("[INFO] No NetFlow collectors configured")
	} else {
		for _, f := range flowCollectors {
			go f.Start()
		}
		log.Printf("[INFO] %d NetFlow collector(s) started", len(flowCollectors))
	}

	for _, f := range flowCollectors {
		if netflow, ok := f.(*collectors.Netflow); ok && netflow.FlowChannel != nil {
			go func(n *collectors.Netflow) {
				counter := 0
				for raw := range n.FlowChannel {
					dlog("Flow: Proto=%v Src=%v Dst=%v",
						raw[fields.PROTOCOL], raw[fields.IPV4_SRC_ADDR], raw[fields.IPV4_DST_ADDR])

					fr := flow.ConvertToFlowRecord(raw)
					batcher.Add(fr)

					if engine != nil {
						engine.AddFlow(detection.Flow{
							Timestamp: fr.TimestampEnd,
							SrcIP:     fr.SrcHost,
							DstIP:     fr.DstHost,
							SrcPort:   fr.SrcPort,
							DstPort:   fr.DstPort,
							Proto:     detection.ProtocolToString(fr.Proto),
							TCPFlags:  fr.TCPFlags,
							Packets:   fr.Packets,
							Bytes:     fr.Bytes,
						})
					}

					counter++
					if counter%100000 == 0 {
						log.Printf("[NETFLOW] Processed %d flows", counter)
					}
				}
			}(netflow)
		}
	}

	// ── Detection engine ──────────────────────────────────────────────────────
	if cfg.Detection.Enabled {
		detection.InitDebugDetection(cfg.Detection.DebugDetection)
		log.Print("[INFO] Detection engine enabled")

		detectionRules, err = detection.LoadDetectionRules(cfg.Detection.RulesConfig)
		if err != nil {
			log.Fatalf("Failed to load detection rules: %v", err)
		}
		log.Printf("[INFO] Loaded %d detection rules", len(detectionRules))

		maxWin := 10 * time.Second
		if cfg.Detection.FlowCacheMaxWindow != "" {
			if d, err := time.ParseDuration(cfg.Detection.FlowCacheMaxWindow); err == nil {
				maxWin = d
			} else {
				log.Printf("[WARN] Invalid flow_cache_max_window: %v", err)
			}
		}

		var store detection.DetectionStore
		if db != nil {
			store = detection.NewSQLiteStore(db)
			log.Println("[INFO] Using SQLite detection store")
		} else {
			store = detection.NewMemoryStore()
			log.Println("[WARN] Using in-memory detection store")
		}

		engine = detection.NewEngine(detectionRules, cfg.MyASN, myNets, maxWin, enrichers.Geo, enrichers.DNS, store)
		engine.SetClickHouseWriter(detection.NewClickHouseWriter())
		if cfm != nil {
			engine.SetReporter(cfm)
		}

		if cfg.Detection.Anomaly.Enabled {
			_, _ = detection.StartAnomalyStack(ctx, cfg, engine, store, configPath)
		}

		go engine.Run(ctx)
		log.Printf("[INFO] Detection engine started (maxWindow=%s)", maxWin)
	} else {
		log.Print("[INFO] Detection engine disabled")
	}

	// ── API ───────────────────────────────────────────────────────────────────
	go func() {
		api.Geo = geo
		api.DB = db
		api.Resolver = resolver
		if listener != nil {
			api.Ranger = listener.Ranger
		}
		api.TelemetryDB = db
		api.CFM = cfm
		api.Start()
	}()

	<-ctx.Done()
	log.Println("Shutdown complete.")
}

