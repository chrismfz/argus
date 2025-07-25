package detection

import (
    "fmt"
    "net"
//    "os"
    "strings"
    "time"
)

// 🔎 Ελέγχει αν ένας rule ταιριάζει με πρόσφατα flows
func evaluateRule(rule DetectionRule, flows []Flow, myNets []*net.IPNet) (bool, []Flow) {
    now := time.Now()
    window, err := time.ParseDuration(rule.TimeWindow)
    if err != nil {
        return false, nil // invalid rule
    }
    cutoff := now.Add(-window)

    type key struct {
        Src string
        Dst string
    }
    groups := make(map[key][]Flow)

    for _, f := range flows {
        if f.Timestamp.Before(cutoff) {
            continue
        }
        if rule.Proto != "" && strings.ToLower(f.Proto) != strings.ToLower(rule.Proto) {
            continue
        }
        if rule.DstPort != 0 && f.DstPort != rule.DstPort {
            continue
        }
        if rule.TCPFlags != "" && !matchTCPFlags(f.TCPFlags, rule.TCPFlags) {
            continue
        }
        if (rule.SameDstIP || rule.SameDstPort || rule.MinUniqueSrcIPs > 0 || rule.UniqueDstIPs > 0) && !isMyPrefix(f.DstIP, myNets) {
            continue
        }

        var k key
        if rule.SameDstIP {
            k = key{Src: f.SrcIP, Dst: f.DstIP}
        } else if rule.SameDstPort {
            k = key{Src: f.SrcIP, Dst: fmt.Sprintf("port:%d", f.DstPort)}
        } else {
            k = key{Src: f.SrcIP, Dst: "any"}
        }

        groups[k] = append(groups[k], f)
    }

    for _, group := range groups {
        if len(group) < rule.MinFlows {
            continue
        }

        uniquePorts := make(map[uint16]struct{})
        uniqueSrcs := make(map[string]struct{})
        uniqueDstIPs := make(map[string]struct{})
        totalPackets := uint64(0)
        totalSeconds := float64(0)

        for _, f := range group {
            uniquePorts[f.DstPort] = struct{}{}
            uniqueSrcs[f.SrcIP] = struct{}{}
            uniqueDstIPs[f.DstIP] = struct{}{}
            totalPackets += f.Packets
            duration := f.Packets // fallback, we don't have exact duration, may refine later
            if duration > 0 {
                totalSeconds += float64(duration)
            }
        }

        if rule.UniqueDstPorts > 0 && len(uniquePorts) < rule.UniqueDstPorts {
            continue
        }

        if rule.MinUniqueSrcIPs > 0 && len(uniqueSrcs) < rule.MinUniqueSrcIPs {
            continue
        }

        if rule.UniqueDstIPs > 0 && len(uniqueDstIPs) < rule.UniqueDstIPs {
            continue
        }

        if rule.MinAvgPPS > 0 && totalSeconds > 0 {
            avgPps := float64(totalPackets) / totalSeconds
            if avgPps < float64(rule.MinAvgPPS) {
                continue
            }
        }

        return true, group
    }

    return false, nil
}

func matchTCPFlags(flowFlags uint8, required string) bool {
    required = strings.ToUpper(required)
    switch required {
    case "SYN":
        return flowFlags&0x02 != 0
    case "ACK":
        return flowFlags&0x10 != 0
    case "SYN-ACK":
        return (flowFlags&0x02 != 0) && (flowFlags&0x10 != 0)
    default:
        return false
    }
}

func isMyPrefix(ipStr string, nets []*net.IPNet) bool {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return false
    }
    for _, n := range nets {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}

// ✨ Συμπυκνώνει το γιατί ενεργοποιήθηκε ο rule (για log reason)
func buildReason(rule DetectionRule) string {
    var parts []string
    if rule.MinFlows > 0 {
        parts = append(parts, fmt.Sprintf("min_flows=%d", rule.MinFlows))
    }
    if rule.MinUniqueSrcIPs > 0 {
        parts = append(parts, fmt.Sprintf("unique_srcs>=%d", rule.MinUniqueSrcIPs))
    }
    if rule.UniqueDstPorts > 0 {
        parts = append(parts, fmt.Sprintf("dst_ports>=%d", rule.UniqueDstPorts))
    }
    if rule.UniqueDstIPs > 0 {
        parts = append(parts, fmt.Sprintf("dst_ips>=%d", rule.UniqueDstIPs))
    }
    if rule.MinAvgPPS > 0 {
        parts = append(parts, fmt.Sprintf("avg_pps>=%d", rule.MinAvgPPS))
    }
    if rule.TCPFlags != "" {
        parts = append(parts, fmt.Sprintf("tcp_flags=%s", rule.TCPFlags))
    }
    return strings.Join(parts, ", ")
}
