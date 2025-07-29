package detection

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type DetectionRule struct {
	Name              string `yaml:"name"`
	Proto             string `yaml:"proto"`
	DstPort           uint16 `yaml:"dst_port,omitempty"`
	SameDstIP         bool   `yaml:"same_dst_ip,omitempty"`
	SameDstPort       bool   `yaml:"same_dst_port,omitempty"`
	UniqueDstPorts    int    `yaml:"unique_dst_ports,omitempty"`
	UniqueDstIPs      int    `yaml:"unique_dst_ips,omitempty"`
	MinFlows          int    `yaml:"min_flows,omitempty"`
	MinUniqueSrcIPs   int    `yaml:"min_unique_src_ips,omitempty"`
	MinAvgPPS         int    `yaml:"min_avg_pps,omitempty"`
	TCPFlags          string `yaml:"tcp_flags,omitempty"`
	TimeWindow        string `yaml:"time_window"`
	Action            string `yaml:"action"`
	BlackholeCount       int      `yaml:"blackhole_count,omitempty"`
	BlackholeNextHop     string   `yaml:"blackhole_next_hop,omitempty"`
	BlackholeCommunities []string `yaml:"blackhole_communities,omitempty"`
	BlackholeTime        int      `yaml:"blackhole_time,omitempty"` // seconds
}

type RuleSet struct {
	Rules []DetectionRule `yaml:"rules"`
}

func LoadDetectionRules(path string) ([]DetectionRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read detection rules: %w", err)
	}
	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("failed to parse detection rules: %w", err)
	}
	return ruleSet.Rules, nil
}
