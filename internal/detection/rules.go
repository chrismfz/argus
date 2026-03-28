package detection

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type DetectionRule struct {
	Name              string `yaml:"name"`
	Proto             string `yaml:"proto"`
	DstPort           interface{} `yaml:"dst_port,omitempty"` // int ή []int
        SrcPort           interface{} `yaml:"src_port,omitempty"` // int | []int | "1000-2000"
	SameDstIP         bool   `yaml:"same_dst_ip,omitempty"`
	SameDstPort       bool   `yaml:"same_dst_port,omitempty"`
    SameSrcIP         bool   `yaml:"same_src_ip,omitempty"`
    SameSrcPort       bool   `yaml:"same_src_port,omitempty"`
	UniqueDstPorts    int    `yaml:"unique_dst_ports,omitempty"`
	UniqueDstIPs      int    `yaml:"unique_dst_ips,omitempty"`
	MinFlows          int    `yaml:"min_flows,omitempty"`
	MinUniqueSrcIPs   int    `yaml:"min_unique_src_ips,omitempty"`
	MinAvgPPS         int    `yaml:"min_avg_pps,omitempty"`
	TCPFlags          string `yaml:"tcp_flags,omitempty"`

    Direction         string `yaml:"direction,omitempty"`
    MinBytes          uint64 `yaml:"min_bytes,omitempty"`
    MinPackets        uint64 `yaml:"min_packets,omitempty"`
    MinTotalBytes     uint64 `yaml:"min_total_bytes,omitempty"`
    NATPresent        bool   `yaml:"nat_present,omitempty"`
    TTLMin            uint8  `yaml:"ttl_min,omitempty"`
    TTLMax            uint8  `yaml:"ttl_max,omitempty"`

	TimeWindow        string `yaml:"time_window"`
	Action            string `yaml:"action"`
	BlackholeCount       int      `yaml:"blackhole_count,omitempty"`
	BlackholeNextHop     string   `yaml:"blackhole_next_hop,omitempty"`
	BlackholeCommunities []string `yaml:"blackhole_communities,omitempty"`
	BlackholeTime        interface{} `yaml:"blackhole_time,omitempty"` // int ή []int; 0 = permanent

    // Safety & targeting
    BlackholeTarget      string   `yaml:"blackhole_target,omitempty"`      // "src" (default) | "dst"
    ExcludeDstIPs        []string `yaml:"exclude_dst_ips,omitempty"`       // exact IPs
    ExcludeSrcIPs        []string `yaml:"exclude_src_ips,omitempty"`
    OnlyPrefixes         []string `yaml:"only_prefixes,omitempty"`         // if set, match only if (src OR dst) in these CIDRs

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




// 0 is permanent (χωρίς auto-withdraw).
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
        case []int:
                out := make([]uint16, 0, len(v))
                for _, n := range v { out = append(out, uint16(n)) }
                return out
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
                        case string:
                                var a,b int
                                if _,err := fmt.Sscanf(t, "%d-%d", &a,&b); err==nil && a>=0 && b>=a && b<=65535 {
                                        for p:=a; p<=b; p++ { out = append(out, uint16(p)) }
                                }
			}

		}
		return out

        case string:
                // support single "80" or range "1000-2000"
                var a,b int
                if _,err := fmt.Sscanf(v, "%d-%d", &a,&b); err==nil && a>=0 && b>=a && b<=65535 {
                        out := make([]uint16, 0, b-a+1)
                        for p:=a; p<=b; p++ { out = append(out, uint16(p)) }
                        return out
                }
                var one int
                if _,err := fmt.Sscanf(v, "%d", &one); err==nil && one>=0 && one<=65535 {
                        return []uint16{uint16(one)}
                }
                return nil

	default:
		return nil
	}
}


// Mirror for SrcPort, same semantics as DstPorts()
func (r *DetectionRule) SrcPorts() []uint16 {
    switch v := r.SrcPort.(type) {
    case int:
        return []uint16{uint16(v)}
    case int64:
        return []uint16{uint16(v)}
    case float64:
        return []uint16{uint16(v)}
    case []int:
        out := make([]uint16, 0, len(v))
        for _, n := range v { out = append(out, uint16(n)) }
        return out
    case []interface{}:
        out := make([]uint16, 0, len(v))
        for _, e := range v {
            switch t := e.(type) {
            case int:     out = append(out, uint16(t))
            case int64:   out = append(out, uint16(t))
            case float64: out = append(out, uint16(t))
            case string:
                var a,b int
                if _,err := fmt.Sscanf(t, "%d-%d", &a,&b); err==nil && a>=0 && b>=a && b<=65535 {
                    for p:=a; p<=b; p++ { out = append(out, uint16(p)) }
                }
            }
        }
        return out
    case string:
        var a,b int
        if _,err := fmt.Sscanf(v, "%d-%d", &a,&b); err==nil && a>=0 && b>=a && b<=65535 {
            out := make([]uint16, 0, b-a+1)
            for p:=a; p<=b; p++ { out = append(out, uint16(p)) }
            return out
        }
        var one int
        if _,err := fmt.Sscanf(v, "%d", &one); err==nil && one>=0 && one<=65535 {
            return []uint16{uint16(one)}
        }
        return nil
    case nil:
        return nil
    default:
        return nil
    }
}
