package main

import (
    "os"
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

func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var cfg Config
    err = yaml.Unmarshal(data, &cfg)
    if err != nil {
        return nil, err
    }
    return &cfg, nil
}
