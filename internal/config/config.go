package config

import (
	"argus/internal/collectors"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BGPListenerConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ListenIP    string `yaml:"listen_ip"`
	ASN         uint32 `yaml:"asn"`
	RemoteASN   uint32 `yaml:"remote_asn"` // Το ASN του peer (π.χ. MikroTik)
	LocalASN    uint32 `yaml:"local_asn"`
	RouterID    string `yaml:"router_id"`
	PeerIP      string `yaml:"peer_ip"` // the MikroTik’s IP
	MaxPeers    int    `yaml:"max_peers"`
	DumpEnabled bool   `yaml:"dump_enabled"`
	StoreASPath bool   `yaml:"store_aspath"`
}

type BGPConfig struct {
	TableFile string            `yaml:"table_file"`
	Listener  BGPListenerConfig `yaml:"bgp_listener"`
}

type FrontendConfig struct {
	Type   string
	Config map[string]string
	// Exporters string // Removed, as debug flag will handle stdout
}

type RouterOSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Address        string `yaml:"address"` // "http://84.54.49.1" or "https://..."
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	InsecureTLS    bool   `yaml:"insecure_tls"`    // accept self-signed certs
	TimeoutSeconds int    `yaml:"timeout_seconds"` // default 10
}

type PathfinderConfig struct {
	CommunityMap  map[string]string `yaml:"community_map"`
	TransitASNMap map[uint32]string `yaml:"transit_asn_map"`
	NextHopMap    map[string]string `yaml:"nexthop_map"`
}

// ✅ Το κύριο Config struct
type Config struct {
	BGP        BGPConfig                 `yaml:"bgp"`
	Collectors map[string]FrontendConfig `yaml:"collectors"`
	Enrich     string                    `yaml:"enrich"`

	CFM        CFMConfig        `yaml:"cfm"`
	RouterOS   RouterOSConfig   `yaml:"routeros"`
	Pathfinder PathfinderConfig `yaml:"pathfinder"`

	MaxMind MaxMindConfig `yaml:"maxmind"`
	GeoIP   struct {
		ASNDB  string // derived, not from yaml
		CityDB string // derived, not from yaml
		// CacheMaxEntries bounds each per-IP GeoIP lookup cache (ASN name,
		// ASN number, country, city). 0 = default (250000), negative =
		// unlimited — same semantics as the retention/cap knobs.
		CacheMaxEntries int `yaml:"cache_max_entries"`
	} `yaml:"geoip"`

	DNS struct {
		Nameserver      string `yaml:"nameserver"`
		BatchSize       int    `yaml:"batch_size"` // προαιρετικό, default θα μπει αν λείπει
		SecondsInterval int    `yaml:"seconds_interval"`
		LookbackMinutes int    `yaml:"lookback_minutes"`
		SkipPrivate     bool   `yaml:"skip_private"`
		MaxThreads      int    `yaml:"max_threads"`
	} `yaml:"dns"`

	Timezone string `yaml:"timezone"`
	Debug    bool   `yaml:"debug"`

	MyASN              uint32   `yaml:"my_asn"`
	MyPrefixes         []string `yaml:"my_prefixes"`
	UpstreamInterfaces []uint32 `yaml:"upstream_interfaces"`

	SNMP SNMPConfig `yaml:"snmp"`

	Detection struct {
		Enabled            bool   `yaml:"enable_detection_engine"`
		RulesConfig        string `yaml:"rules_config"`
		FlowCacheMaxWindow string `yaml:"flow_cache_max_window"`
		DebugDetection     bool   `yaml:"debug_detection"`

		Anomaly struct {
			// Core on/off + scheduling
			Enabled      bool   `yaml:"enabled"`
			DebugAll     bool   `yaml:"debug_all"` // αν true: γράφουμε ΟΛΑ τα scored src στο anomalies.log
			Window       string `yaml:"window"`    // π.χ. "60s"
			Interval     string `yaml:"interval"`  // π.χ. "10s"
			Label        string `yaml:"label"`
			RetrainEvery string `yaml:"retrain_every"` // π.χ. "30m"
			BaselineMax  int    `yaml:"baseline_max"`
			TopK         int    `yaml:"top_k"`

			// Model (ίδια με πριν)
			Trees         int     `yaml:"trees"`
			SampleSize    int     `yaml:"sample_size"`
			Contamination float64 `yaml:"contamination"`

			// Προαιρετικό gate: απαιτεί HBOS < τα p-ποσοστημόριο (0 < p < 1). Βάλε 0 για απενεργοποίηση.
			RequireHBOSPercentile float64 `yaml:"require_hbos_percentile"` // π.χ. 0.99

			// Προαιρετικό gate για eHBOS
			RequireEHBOSPercentile float64 `yaml:"require_ehbos_percentile"` // π.χ. 0.98

			// Fusion βάρη & printing κατώφλι
			Weights struct {
				IForest float64 `yaml:"iforest"` // e.g. 0.55
				HBOS    float64 `yaml:"hbos"`    // e.g. 0.15
				EHBOS   float64 `yaml:"ehbos"`   // e.g. 0.30
			} `yaml:"weights"`
			PrintAboveMeanPercent float64 `yaml:"print_above_mean_percent"` // π.χ. 25 = mean * 1.25

			// (Προαιρετικό) Παράμετροι eHBOS ensemble — αν δεν οριστούν, χρησιμοποιούνται default από τον ανιχνευτή.
			EHBOS struct {
				Bins      int     `yaml:"bins"`      // π.χ. 12
				Eps       float64 `yaml:"eps"`       // π.χ. 1e-6
				Subspaces int     `yaml:"subspaces"` // π.χ. 12
				Size      int     `yaml:"size"`      // π.χ. 3 (features per subspace)
				Agg       string  `yaml:"agg"`       // "max" | "mean"
			} `yaml:"ehbos"`

			// Allowlist of source ASNs to suppress (e.g. Cloudflare 13335, your ASN, etc.)
			AllowASNs []uint32 `yaml:"allow_asns"`

			// Απλός προ-φίλτρος για μείωση θορύβου
			Prefilter struct {
				MinPPS          float64 `yaml:"min_pps"`
				MinUniqDstPorts float64 `yaml:"min_uniq_dst_ports"`
				MinUniqDstIPs   float64 `yaml:"min_uniq_dst_ips"`
				MinSynRatio     float64 `yaml:"min_syn_ratio"`
				MinICMPShare    float64 `yaml:"min_icmp_share"`
			} `yaml:"prefilter"`

			// ── ΠΕΡΙΣΣΕΥΜΑ / Back-compat (προαιρετικά, δεν χρησιμοποιούνται στη νέα λογική)
			MinScore float64 `yaml:"min_score"` // παλιό
			LogOnly  bool    `yaml:"log_only"`  // παλιό
			Debug    bool    `yaml:"debug"`     // παλιό
		} `yaml:"anomaly"`

		// in config.go (inside type Config { Detection struct { ... } })
		Memory struct {
			Enabled  bool   `yaml:"enabled"`
			Interval string `yaml:"interval"`
			LogPath  string `yaml:"log_path"`

			Alpha   float64 `yaml:"alpha"`
			Theta   float64 `yaml:"theta"`
			TauRisk float64 `yaml:"tau_risk"`

			Debt struct {
				DecayPerTick  float64 `yaml:"decay_per_tick"`
				WarnThreshold float64 `yaml:"warn_threshold"`
			} `yaml:"debt"`

			Flags struct {
				SpikeThreshold float64 `yaml:"spike_threshold"`
				Decay5m        float64 `yaml:"decay_5m"`
				Decay30m       float64 `yaml:"decay_30m"`
				ConsecHighWarn int     `yaml:"consec_high_warn"`
			} `yaml:"flags"`

			TTL                 string `yaml:"ttl"`
			TopKEnrich          int    `yaml:"top_k_enrich"`
			LogStateChangesOnly bool   `yaml:"log_state_changes_only"`
		} `yaml:"memory"`
	} `yaml:"detection"`

	Auth AuthConfig `yaml:"auth"`

	API struct {
		ListenAddress string   `yaml:"listen_address"`
		Port          int      `yaml:"port"`
		Tokens        []string `yaml:"tokens"`
		AllowIPs      []string `yaml:"allow_ips"`
	} `yaml:"api"`

	IPProfile struct {
		StaleAfter      time.Duration `yaml:"stale_after"`
		Retention       time.Duration `yaml:"retention"`
		CleanupInterval time.Duration `yaml:"cleanup_interval"`
		MaxEntries      int           `yaml:"max_entries"`
	} `yaml:"ip_profile"`

	Flowstore FlowstoreConfig `yaml:"flowstore"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Retention RetentionConfig `yaml:"retention"`
	FlowLog   FlowLogConfig   `yaml:"flowlog"`
}

// FlowLogConfig controls the optional raw flow log (ROADMAP Phase 2, Tier 0):
// an enriched 5-tuple record per flow written to a dedicated SQLite file and
// pruned by size, not age — the forensic "what did IP X do at 03:00?" store.
// Disabled by default; it is the only argus feature that can write a lot.
type FlowLogConfig struct {
	Enabled    bool    `yaml:"enabled"`     // default false (opt-in)
	DBPath     string  `yaml:"db_path"`     // default "flows.sqlite" (dedicated file)
	MaxGB      float64 `yaml:"max_gb"`      // size budget; oldest rows pruned past it. unset/0 = default 20; NEGATIVE = unbounded
	SampleRate int     `yaml:"sample_rate"` // write 1 of every N flows, default 1 (every flow)
	BufferSize int     `yaml:"buffer_size"` // in-memory queue depth; flows dropped (counted) when full, default 65536
	BatchSize  int     `yaml:"batch_size"`  // rows per insert transaction, default 1000
}

// FlowstoreConfig controls how much per-ASN aggregate data survives to SQLite.
// Zero values mean "use the default"; -1 means unlimited (top-N caps) or
// keep-forever (retentions). See ROADMAP Phase 1.
type FlowstoreConfig struct {
	RetentionDays         int `yaml:"retention_days"`          // detail tables (top IPs/prefixes/ports/…), default 7
	TimelineRetentionDays int `yaml:"timeline_retention_days"` // 5-min timeline tables, default 30
	DailyRetentionDays    int `yaml:"daily_retention_days"`    // Tier-2 daily rollups, default 730 (2 years)
	TopIPs                int `yaml:"top_ips"`                 // IP pairs written per (bucket, asn, dir), default 50
	TopPrefixes           int `yaml:"top_prefixes"`            // default 20
	TopPorts              int `yaml:"top_ports"`               // default 10
	MaxTrackedIPs         int `yaml:"max_tracked_ips"`         // unique IP pairs tracked in RAM per bucket, default 10000
	MaxTrackedPrefixes    int `yaml:"max_tracked_prefixes"`    // default 1000
	MaxTrackedPorts       int `yaml:"max_tracked_ports"`       // default 500
}

// TelemetryConfig controls the minute-bucket time series retention.
type TelemetryConfig struct {
	BucketRetentionDays int `yaml:"bucket_retention_days"` // telemetry_*_buckets tables, default 30
}

// RetentionConfig groups the cleanup-ticker retentions for the detection-side
// tables. Zero values mean "use the default"; negative disables pruning.
type RetentionConfig struct {
	Detections            time.Duration `yaml:"detections"`                // detections table by last_seen, default 90d
	AlertEvents           time.Duration `yaml:"alert_events"`              // alert_events (+deliveries via FK), default 90d
	SnapshotsDaily        time.Duration `yaml:"snapshots_daily"`           // 'daily' snapshots only, default 400d
	RiskEvents            time.Duration `yaml:"risk_events"`               // risk_events table, default 7d
	BlackholeEvents       time.Duration `yaml:"blackhole_events"`          // blackhole_events audit log, default 90d
	BlackholeEventsMaxRow int           `yaml:"blackhole_events_max_rows"` // hard row cap, default 10000
}

type SNMPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Target    string `yaml:"target"`
	Community string `yaml:"community"`
	Port      uint16 `yaml:"port"`
	Timeout   int    `yaml:"timeout"` // seconds
	Retries   int    `yaml:"retries"`
}

type CFMConfig struct {
	Enabled bool   `yaml:"enabled"` // on/off
	URL     string `yaml:"url"`     // e.g. https://cfm.example.com
	Token   string `yaml:"token"`   // shared token (header "Token")
}

type AuthConfig struct {
	DBPath        string        `yaml:"db_path"`
	SessionDBPath string        `yaml:"session_db_path"`
	SessionTTL    time.Duration `yaml:"session_ttl"`
	IdleTimeout   time.Duration `yaml:"idle_timeout"`
	SecureCookie  bool          `yaml:"secure_cookie"`
	CookieName    string        `yaml:"cookie_name"`

	// MFAEncryptionKey is the symmetric key goauth uses to encrypt TOTP
	// secrets at rest. Required once goauth has MFA support. Accepts a raw
	// 16/24/32-byte string, hex, or base64. If empty, goauth falls back to
	// the GOAUTH_MFA_ENCRYPTION_KEY environment variable.
	MFAEncryptionKey string `yaml:"mfa_encryption_key"`
	// MFAIssuer is the issuer label shown in authenticator apps (otpauth:// URI).
	MFAIssuer string `yaml:"mfa_issuer"`

	// WebAuthn / passkey support (optional). WebAuthnRPID enables the
	// WebAuthn endpoints when set (the effective domain, e.g. "argus.example.com").
	WebAuthnRPID          string   `yaml:"webauthn_rpid"`
	WebAuthnRPDisplayName string   `yaml:"webauthn_rp_display_name"`
	WebAuthnOrigins       []string `yaml:"webauthn_origins"`
}

// Add this struct (alongside SNMPConfig, CFMConfig etc.)
type MaxMindConfig struct {
	Enabled     bool          `yaml:"enabled"`
	AccountID   string        `yaml:"account_id"`
	LicenseKey  string        `yaml:"license_key"`
	DBPath      string        `yaml:"db_path"`
	Editions    []string      `yaml:"editions"`
	CheckEvery  time.Duration `yaml:"check_every"`
	MinAge      time.Duration `yaml:"min_age"`
	HTTPTimeout time.Duration `yaml:"http_timeout"`
}

func GetDefaultConfigPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	binDir := filepath.Dir(exePath)

	pathsToTry := []string{
		filepath.Join(binDir, "config.yaml"),                      // bin/config.yaml
		filepath.Join(binDir, "etc", "config.yaml"),               // bin/etc/config.yaml
		filepath.Join(filepath.Dir(binDir), "etc", "config.yaml"), // ../etc/config.yaml
	}

	for _, path := range pathsToTry {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("config.yaml not found in: \n- %s\n- %s\n- %s",
		pathsToTry[0], pathsToTry[1], pathsToTry[2])
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error parsing config file %s: %w", path, err)
	}

	// Derive GeoIP paths from MaxMind config
	if cfg.MaxMind.DBPath != "" {
		cfg.GeoIP.ASNDB = filepath.Join(cfg.MaxMind.DBPath, "GeoLite2-ASN.mmdb")
		cfg.GeoIP.CityDB = filepath.Join(cfg.MaxMind.DBPath, "GeoLite2-City.mmdb")
	}

	if cfg.IPProfile.StaleAfter <= 0 {
		cfg.IPProfile.StaleAfter = 24 * time.Hour
	}
	if cfg.IPProfile.Retention <= 0 {
		cfg.IPProfile.Retention = 30 * 24 * time.Hour
	}
	if cfg.IPProfile.CleanupInterval <= 0 {
		cfg.IPProfile.CleanupInterval = 15 * time.Minute
	}
	if cfg.IPProfile.MaxEntries <= 0 {
		cfg.IPProfile.MaxEntries = 10_000
	}

	applyStorageDefaults(&cfg)
	return &cfg, nil
}

// applyStorageDefaults fills in the Phase-1 storage knobs. Semantics for every
// field: 0 (unset) → the pre-Phase-1 hardcoded value, so existing deployments
// keep their exact behaviour; negative → "unlimited" for top-N/track caps and
// "keep forever" (pruning disabled) for retentions.
func applyStorageDefaults(cfg *Config) {
	defInt := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	defDur := func(v *time.Duration, def time.Duration) {
		if *v == 0 {
			*v = def
		}
	}

	fs := &cfg.Flowstore
	defInt(&fs.RetentionDays, 7)
	defInt(&fs.TimelineRetentionDays, 30)
	defInt(&fs.DailyRetentionDays, 730)
	defInt(&fs.TopIPs, 50)
	defInt(&fs.TopPrefixes, 20)
	defInt(&fs.TopPorts, 10)
	defInt(&fs.MaxTrackedIPs, 10000)
	defInt(&fs.MaxTrackedPrefixes, 1000)
	defInt(&fs.MaxTrackedPorts, 500)

	defInt(&cfg.Telemetry.BucketRetentionDays, 30)

	r := &cfg.Retention
	defDur(&r.Detections, 90*24*time.Hour)
	defDur(&r.AlertEvents, 90*24*time.Hour)
	defDur(&r.SnapshotsDaily, 400*24*time.Hour)
	defDur(&r.RiskEvents, 7*24*time.Hour)
	defDur(&r.BlackholeEvents, 90*24*time.Hour)
	defInt(&r.BlackholeEventsMaxRow, 10000)

	// FlowLog — only normalise the operational knobs; Enabled stays as set
	// (default false) and MaxGB<=0 is a valid "no cap" so it is left alone.
	fl := &cfg.FlowLog
	if fl.DBPath == "" {
		fl.DBPath = "flows.sqlite"
	}
	if fl.MaxGB == 0 {
		fl.MaxGB = 20
	}
	defInt(&fl.SampleRate, 1)
	defInt(&fl.BufferSize, 65536)
	defInt(&fl.BatchSize, 1000)
}

func (gc Config) GetCollectors() []collectors.Frontend {
	var r []collectors.Frontend
	for n, fields := range gc.Collectors {
		switch n {
		case "netflow":
			f := collectors.Netflow{}
			f.Configure(fields.Config)
			r = append(r, &f)
		default:
			panic(fmt.Sprintf("Error: Invalid collector type %v", n))
		}
	}
	return r
}

var AppConfig *Config

func GetMyASN() uint32 {
	if AppConfig != nil {
		return AppConfig.MyASN
	}
	return 0
}

func GetLocalASN() uint32 {
	if AppConfig != nil {
		return AppConfig.BGP.Listener.LocalASN
	}
	return 0
}

// EnrichEnabled reports whether a named enrichment module is active.
func EnrichEnabled(cfg *Config, name string) bool {
	if strings.ToLower(cfg.Enrich) == "none" {
		return false
	}
	for _, p := range strings.Split(strings.ToLower(cfg.Enrich), ",") {
		if strings.TrimSpace(p) == name {
			return true
		}
	}
	return false
}

// LogStartup prints the effective configuration at startup.
func LogStartup(cfg *Config) {
	fs, tel, r := cfg.Flowstore, cfg.Telemetry, cfg.Retention
	log.Printf("[CFG] storage: flowstore(detail=%dd timeline=%dd daily=%dd top{ips:%d,pfx:%d,ports:%d} track{ips:%d,pfx:%d,ports:%d}) telemetry_buckets=%dd",
		fs.RetentionDays, fs.TimelineRetentionDays, fs.DailyRetentionDays,
		fs.TopIPs, fs.TopPrefixes, fs.TopPorts,
		fs.MaxTrackedIPs, fs.MaxTrackedPrefixes, fs.MaxTrackedPorts,
		tel.BucketRetentionDays)
	log.Printf("[CFG] retention: detections=%s alert_events=%s snapshots_daily=%s risk_events=%s blackhole_events=%s (max_rows=%d)",
		r.Detections, r.AlertEvents, r.SnapshotsDaily, r.RiskEvents, r.BlackholeEvents, r.BlackholeEventsMaxRow)

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

	mc := cfg.Detection.Memory
	log.Printf("[CFG] memory: enabled=%v interval=%s log_path=%s alpha=%.2f theta=%.2f tau_risk=%.2f",
		mc.Enabled, mc.Interval, mc.LogPath, mc.Alpha, mc.Theta, mc.TauRisk)
	log.Printf("[CFG] memory: debt(decay=%.2f warn=%.2f) flags(spike=%.2f consec=%d d5m=%.3f d30m=%.3f) ttl=%s top_k_enrich=%d state_changes_only=%v",
		mc.Debt.DecayPerTick, mc.Debt.WarnThreshold, mc.Flags.SpikeThreshold, mc.Flags.ConsecHighWarn,
		mc.Flags.Decay5m, mc.Flags.Decay30m, mc.TTL, mc.TopKEnrich, mc.LogStateChangesOnly)
}
