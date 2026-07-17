package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadFromYAML(t *testing.T, yamlBody string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yamlBody), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

// TestStorageDefaults verifies that an empty config resolves to the exact
// pre-Phase-1 hardcoded values, so existing deployments keep their behaviour.
func TestStorageDefaults(t *testing.T) {
	cfg := loadFromYAML(t, "my_asn: 65000\n")

	fs := cfg.Flowstore
	if fs.RetentionDays != 7 || fs.TimelineRetentionDays != 30 {
		t.Fatalf("flowstore retention defaults wrong: %+v", fs)
	}
	if fs.TopIPs != 50 || fs.TopPrefixes != 20 || fs.TopPorts != 10 {
		t.Fatalf("flowstore top-N defaults wrong: %+v", fs)
	}
	if fs.MaxTrackedIPs != 10000 || fs.MaxTrackedPrefixes != 1000 || fs.MaxTrackedPorts != 500 {
		t.Fatalf("flowstore track cap defaults wrong: %+v", fs)
	}
	if cfg.Telemetry.BucketRetentionDays != 30 {
		t.Fatalf("telemetry default wrong: %+v", cfg.Telemetry)
	}
	r := cfg.Retention
	if r.Detections != 90*24*time.Hour || r.AlertEvents != 90*24*time.Hour {
		t.Fatalf("retention defaults wrong: %+v", r)
	}
	if r.SnapshotsDaily != 400*24*time.Hour || r.RiskEvents != 7*24*time.Hour {
		t.Fatalf("retention defaults wrong: %+v", r)
	}
	if r.BlackholeEvents != 90*24*time.Hour || r.BlackholeEventsMaxRow != 10000 {
		t.Fatalf("blackhole_events defaults wrong: %+v", r)
	}

	fl := cfg.FlowLog
	if fl.Enabled {
		t.Fatalf("flow log must be disabled by default")
	}
	if fl.DBPath != "flows.sqlite" || fl.MaxGB != 20 || fl.SampleRate != 1 {
		t.Fatalf("flowlog defaults wrong: %+v", fl)
	}
	if fl.BufferSize != 65536 || fl.BatchSize != 1000 {
		t.Fatalf("flowlog buffer/batch defaults wrong: %+v", fl)
	}
}

func TestFlowLogOverrides(t *testing.T) {
	cfg := loadFromYAML(t, `
flowlog:
  enabled: true
  db_path: /var/lib/argus/flows.sqlite
  max_gb: 50
  sample_rate: 10
`)
	fl := cfg.FlowLog
	if !fl.Enabled || fl.DBPath != "/var/lib/argus/flows.sqlite" || fl.MaxGB != 50 || fl.SampleRate != 10 {
		t.Fatalf("flowlog overrides lost: %+v", fl)
	}
	if fl.BufferSize != 65536 || fl.BatchSize != 1000 {
		t.Fatalf("unset flowlog fields must still default: %+v", fl)
	}
}

// TestStorageOverrides verifies YAML values (including duration strings and
// the negative keep-forever/unlimited sentinel) survive into the config.
func TestStorageOverrides(t *testing.T) {
	cfg := loadFromYAML(t, `
flowstore:
  retention_days: 30
  timeline_retention_days: 90
  top_ips: -1
telemetry:
  bucket_retention_days: 60
retention:
  detections: 720h
  snapshots_daily: -1h
`)

	if cfg.Flowstore.RetentionDays != 30 || cfg.Flowstore.TimelineRetentionDays != 90 {
		t.Fatalf("flowstore overrides lost: %+v", cfg.Flowstore)
	}
	if cfg.Flowstore.TopIPs != -1 {
		t.Fatalf("top_ips -1 (unlimited) must pass through, got %d", cfg.Flowstore.TopIPs)
	}
	if cfg.Flowstore.TopPrefixes != 20 {
		t.Fatalf("unset top_prefixes must still default, got %d", cfg.Flowstore.TopPrefixes)
	}
	if cfg.Telemetry.BucketRetentionDays != 60 {
		t.Fatalf("telemetry override lost: %+v", cfg.Telemetry)
	}
	if cfg.Retention.Detections != 720*time.Hour {
		t.Fatalf("detections=720h lost, got %v", cfg.Retention.Detections)
	}
	if cfg.Retention.SnapshotsDaily >= 0 {
		t.Fatalf("snapshots_daily=-1h (keep forever) must stay negative, got %v", cfg.Retention.SnapshotsDaily)
	}
	if cfg.Retention.AlertEvents != 90*24*time.Hour {
		t.Fatalf("unset alert_events must still default, got %v", cfg.Retention.AlertEvents)
	}
}
