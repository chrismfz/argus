package detection

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type DetectionRule struct {
	Name              string `yaml:"name"`
	Proto             string `yaml:"proto"`
//	DstPort           uint16 `yaml:"dst_port,omitempty"`
	DstPort           interface{} `yaml:"dst_port,omitempty"` // int ή []int
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
//	BlackholeTime        int      `yaml:"blackhole_time,omitempty"` // seconds
	BlackholeTime        interface{} `yaml:"blackhole_time,omitempty"` // int ή []int; 0 = permanent
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




// BlackholeDurations normalizes blackhole_time (int ή λίστα) σε []int.
// 0 σημαίνει permanent (χωρίς auto-withdraw).
func (r *DetectionRule) BlackholeDurations() []int {
	switch v := r.BlackholeTime.(type) {
	case int:
		return []int{v}
	case int64:
		return []int{int(v)}
	case float64:
		return []int{int(v)}
	case []interface{}:
		out := make([]int, 0, len(v))
		for _, e := range v {
			switch t := e.(type) {
			case int:
				out = append(out, t)
			case int64:
				out = append(out, int(t))
			case float64:
				out = append(out, int(t))
			}
		}
		return out
	default:
		return nil
	}
}

// DstPorts normalizes dst_port (int ή λίστα) σε []uint16.
func (r *DetectionRule) DstPorts() []uint16 {
	switch v := r.DstPort.(type) {
	case int:
		return []uint16{uint16(v)}
	case int64:
		return []uint16{uint16(v)}
	case float64:
		return []uint16{uint16(v)}
	case []interface{}:
		out := make([]uint16, 0, len(v))
		for _, e := range v {
			switch t := e.(type) {
			case int:
				out = append(out, uint16(t))
			case int64:
				out = append(out, uint16(t))
			case float64:
				out = append(out, uint16(t))
			}
		}
		return out
	default:
		return nil
	}
}
