package config

import (
    "fmt"
    "os"
    "path/filepath"
    "gopkg.in/yaml.v3"
    "argus/collectors"

)

type BGPListenerConfig struct {
    Enabled     bool   `yaml:"enabled"`
    ListenIP    string `yaml:"listen_ip"`
    ASN         uint32 `yaml:"asn"`
    RemoteASN   uint32 `yaml:"remote_asn"`   // Το ASN του peer (π.χ. MikroTik)
    LocalASN    uint32 `yaml:"local_asn"`
    RouterID    string `yaml:"router_id"`
    PeerIP      string `yaml:"peer_ip"`      // the MikroTik’s IP
    MaxPeers    int    `yaml:"max_peers"`
    DumpEnabled bool   `yaml:"dump_enabled"`
    StoreASPath bool   `yaml:"store_aspath"`
}

type BGPConfig struct {
    TableFile string            `yaml:"table_file"`
    Listener  BGPListenerConfig `yaml:"bgp_listener"`
}


type FrontendConfig struct {
        Type    string
        Config  map[string]string
        // Exporters string // Removed, as debug flag will handle stdout
}


// ✅ Το κύριο Config struct
type Config struct {
    BGP BGPConfig `yaml:"bgp"`
    Collectors map[string]FrontendConfig `yaml:"collectors"`
    Enrich string `yaml:"enrich"`

    CFM CFMConfig `yaml:"cfm"`

    ClickHouse struct {
        Host     string `yaml:"host"`
        User     string `yaml:"user"`
        Password string `yaml:"password"`
        Database string `yaml:"database"`
        Table    string `yaml:"table"`
    } `yaml:"clickhouse"`

    Insert struct {
        BatchSize       int `yaml:"batch_size"`
        FlushIntervalMs int `yaml:"flush_interval_ms"`
    } `yaml:"insert"`

    GeoIP struct {
        ASNDB  string `yaml:"asn_db"`
        CityDB string `yaml:"city_db"`
    } `yaml:"geoip"`


    DNS struct {
        Nameserver string `yaml:"nameserver"`
	BatchSize       int    `yaml:"batch_size"`        // προαιρετικό, default θα μπει αν λείπει
	SecondsInterval int    `yaml:"seconds_interval"`
	LookbackMinutes int    `yaml:"lookback_minutes"`
	SkipPrivate     bool   `yaml:"skip_private"`
	MaxThreads      int    `yaml:"max_threads"`
    } `yaml:"dns"`

    Timezone string `yaml:"timezone"`
    Debug    bool   `yaml:"debug"`

    MyASN     uint32   `yaml:"my_asn"`
    MyPrefixes []string `yaml:"my_prefixes"`

    SNMP SNMPConfig `yaml:"snmp"`


    Detection struct {
        Enabled     bool   `yaml:"enable_detection_engine"`
        RulesConfig string `yaml:"rules_config"`
        FlowCacheMaxWindow string `yaml:"flow_cache_max_window"`
	DebugDetection bool `yaml:"debug_detection"`

        Anomaly struct {
            // Core on/off + scheduling
            Enabled       bool    `yaml:"enabled"`
            DebugAll      bool    `yaml:"debug_all"`         // αν true: γράφουμε ΟΛΑ τα scored src στο anomalies.log
            Window        string  `yaml:"window"`            // π.χ. "60s"
            Interval      string  `yaml:"interval"`          // π.χ. "10s"
            Label         string  `yaml:"label"`
            RetrainEvery  string  `yaml:"retrain_every"`     // π.χ. "30m"
            BaselineMax   int     `yaml:"baseline_max"`
            TopK          int     `yaml:"top_k"`

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
                IForest float64 `yaml:"iforest"`  // e.g. 0.55
                HBOS    float64 `yaml:"hbos"`     // e.g. 0.15
                EHBOS   float64 `yaml:"ehbos"`    // e.g. 0.30
            } `yaml:"weights"`
            PrintAboveMeanPercent float64 `yaml:"print_above_mean_percent"` // π.χ. 25 = mean * 1.25

            // (Προαιρετικό) Παράμετροι eHBOS ensemble — αν δεν οριστούν, χρησιμοποιούνται default από τον ανιχνευτή.
            EHBOS struct {
                Bins       int     `yaml:"bins"`        // π.χ. 12
                Eps        float64 `yaml:"eps"`         // π.χ. 1e-6
                Subspaces  int     `yaml:"subspaces"`   // π.χ. 12
                Size       int     `yaml:"size"`        // π.χ. 3 (features per subspace)
                Agg        string  `yaml:"agg"`         // "max" | "mean"
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
            MinScore      float64 `yaml:"min_score"` // παλιό
            LogOnly       bool    `yaml:"log_only"`  // παλιό
            Debug         bool    `yaml:"debug"`     // παλιό
        } `yaml:"anomaly"`



// in config.go (inside type Config { Detection struct { ... } })
Memory struct {
    Enabled           bool    `yaml:"enabled"`
    Interval          string  `yaml:"interval"`
    LogPath           string  `yaml:"log_path"`

    Alpha             float64 `yaml:"alpha"`
    Theta             float64 `yaml:"theta"`
    TauRisk           float64 `yaml:"tau_risk"`

    Debt struct {
        DecayPerTick   float64 `yaml:"decay_per_tick"`
        WarnThreshold  float64 `yaml:"warn_threshold"`
    } `yaml:"debt"`

    Flags struct {
        SpikeThreshold   float64 `yaml:"spike_threshold"`
        Decay5m          float64 `yaml:"decay_5m"`
        Decay30m         float64 `yaml:"decay_30m"`
        ConsecHighWarn   int     `yaml:"consec_high_warn"`
    } `yaml:"flags"`

    TTL                string  `yaml:"ttl"`
    TopKEnrich         int     `yaml:"top_k_enrich"`
    LogStateChangesOnly bool   `yaml:"log_state_changes_only"`
} `yaml:"memory"`





    } `yaml:"detection"`




API struct {
    ListenAddress string   `yaml:"listen_address"`
    Port          int      `yaml:"port"`
    Tokens        []string `yaml:"tokens"`
    AllowIPs      []string `yaml:"allow_ips"` // CIDR μορφή ή απλές IPs
} `yaml:"api"`

DebugAPI DebugAPIConfig `yaml:"debug_api"`

}

type DebugAPIConfig struct {
    Enabled      bool     `yaml:"enabled"`
    ListenAddress string  `yaml:"listen_address"`
    Port         int      `yaml:"port"`
    AllowIPs     []string `yaml:"allow_ips"`
    RequireToken bool     `yaml:"require_token"`
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
    Enabled bool   `yaml:"enabled"`    // on/off
    URL     string `yaml:"url"`        // e.g. https://cfm.example.com
    Token   string `yaml:"token"`      // shared token (header "Token")
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
		filepath.Join(binDir, "config.yaml"),                        // bin/config.yaml
		filepath.Join(binDir, "etc", "config.yaml"),                 // bin/etc/config.yaml
		filepath.Join(filepath.Dir(binDir), "etc", "config.yaml"),   // ../etc/config.yaml
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
	return &cfg, nil
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
