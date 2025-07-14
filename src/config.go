package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Enrich string `yaml:"enrich"`

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

	BGP struct {
		TableFile string `yaml:"table_file"`
	} `yaml:"bgp"`

	Kafka struct {
		Brokers []string `yaml:"brokers"`
		Topic   string   `yaml:"topic"`
		GroupID string   `yaml:"group_id"`
	} `yaml:"kafka"`

	DNS struct {
		Nameserver string `yaml:"nameserver"`
	} `yaml:"dns"`

	Timezone string `yaml:"timezone"`
	Debug    bool   `yaml:"debug"`
}

// getDefaultConfigPath tries multiple common locations relative to the executable
func getDefaultConfigPath() (string, error) {
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

// LoadConfig reads and parses the YAML config file.
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
