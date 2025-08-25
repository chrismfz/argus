package detection

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DlogEngine is assumed to be available from engine.go as this file is part of the same package.

// 🔎 Ελέγχει αν ένας rule ταιριάζει με πρόσφατα flows
func evaluateRule(rule DetectionRule, flows []Flow, myNets []*net.IPNet) (bool, []Flow) {
	now := time.Now().UTC() // CHANGED: Use UTC for consistent time comparison
	window, err := time.ParseDuration(rule.TimeWindow)
	if err != nil {
		DlogEngine("Invalid TimeWindow for rule %s: %v", rule.Name, err) // CHANGED: Call DlogEngine
		return false, nil // invalid rule
	}
	cutoff := now.Add(-window)
	DlogEngine("Evaluating rule '%s' with %d flows. TimeWindow: %s, Cutoff: %s", rule.Name, len(flows), rule.TimeWindow, cutoff.Format(time.RFC3339)) // CHANGED: Call DlogEngine


	type key struct {
		Src string
		Dst string
	}
	groups := make(map[key][]Flow)

	for _, f := range flows {
		if f.Timestamp.Before(cutoff) {
			DlogEngine("  Flow %s->%s (at %s) is before rule cutoff %s, skipping.", f.SrcIP, f.DstIP, f.Timestamp.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339)) // CHANGED: Call DlogEngine
			continue
		}
		if rule.Proto != "" && strings.ToLower(f.Proto) != strings.ToLower(rule.Proto) {
			DlogEngine("  Flow %s->%s proto mismatch: expected %s, got %s. Skipping.", f.SrcIP, f.DstIP, rule.Proto, f.Proto) // CHANGED: Call DlogEngine
			continue
		}


dstPorts := rule.DstPorts()
if len(dstPorts) > 0 {
    match := false
    for _, p := range dstPorts {
        if f.DstPort == p {
            match = true
            break
        }
    }
    if !match {
        DlogEngine("  Flow %s->%s dst port %d not in rule ports %v. Skipping.",
            f.SrcIP, f.DstIP, f.DstPort, dstPorts)
        continue
    }
}



		if rule.TCPFlags != "" && !matchTCPFlags(f.TCPFlags, rule.TCPFlags) {
			DlogEngine("  Flow %s->%s TCP flags mismatch: expected %s, got %d. Skipping.", f.SrcIP, f.DstIP, rule.TCPFlags, f.TCPFlags) // CHANGED: Call DlogEngine
			continue
		}
		// This condition applies if any of the SameDstIP, SameDstPort, MinUniqueSrcIPs, UniqueDstIPs are relevant
		// For test_all_tcp, none of these are true, so this check will be skipped.
		if (rule.SameDstIP || rule.SameDstPort || rule.MinUniqueSrcIPs > 0 || rule.UniqueDstIPs > 0) && !isMyPrefix(f.DstIP, myNets) {
			DlogEngine("  Flow %s->%s DstIP %s is not in myNets, and rule requires local destination. Skipping.", f.SrcIP, f.DstIP, f.DstIP) // CHANGED: Call DlogEngine
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
		DlogEngine("  Flow %s->%s added to group %v. Group size: %d", f.SrcIP, f.DstIP, k, len(groups[k])) // CHANGED: Call DlogEngine
	}

	if len(groups) == 0 {
		DlogEngine("No groups formed for rule '%s'.", rule.Name) // CHANGED: Call DlogEngine
		return false, nil
	}

	for k, group := range groups {
		DlogEngine("  Evaluating group %v for rule '%s' with %d flows.", k, rule.Name, len(group)) // CHANGED: Call DlogEngine

		if len(group) < rule.MinFlows {
			DlogEngine("    Group size %d less than MinFlows %d. Skipping group.", len(group), rule.MinFlows) // CHANGED: Call DlogEngine
			continue
		}

		uniquePorts := make(map[uint16]struct{})
		uniqueSrcs := make(map[string]struct{})
		uniqueDstIPs := make(map[string]struct{})
		totalPackets := uint64(0)
		
		// To calculate AvgPPS, use the rule's time window as the duration for the group.
		groupDurationSeconds := window.Seconds() 

		for _, f := range group {
			uniquePorts[f.DstPort] = struct{}{}
			uniqueSrcs[f.SrcIP] = struct{}{}
			uniqueDstIPs[f.DstIP] = struct{}{}
			totalPackets += f.Packets
		}

		if rule.UniqueDstPorts > 0 && len(uniquePorts) < rule.UniqueDstPorts {
			DlogEngine("    Unique DstPorts %d less than required %d. Skipping group.", len(uniquePorts), rule.UniqueDstPorts) // CHANGED: Call DlogEngine
			continue
		}

		if rule.MinUniqueSrcIPs > 0 && len(uniqueSrcs) < rule.MinUniqueSrcIPs {
			DlogEngine("    Unique SrcIPs %d less than required %d. Skipping group.", len(uniqueSrcs), rule.MinUniqueSrcIPs) // CHANGED: Call DlogEngine
			continue
		}

		if rule.UniqueDstIPs > 0 && len(uniqueDstIPs) < rule.UniqueDstIPs { 
			DlogEngine("    Unique DstIPs %d less than required %d. Skipping group.", len(uniqueDstIPs), rule.UniqueDstIPs) // CHANGED: Call DlogEngine
			continue
		}

		if rule.MinAvgPPS > 0 {
			if groupDurationSeconds > 0 {
				avgPps := float64(totalPackets) / groupDurationSeconds
				DlogEngine("    Calculated AvgPPS: %.2f (Total Packets: %d, Duration: %.2f s). Required MinAvgPPS: %d", avgPps, totalPackets, groupDurationSeconds, rule.MinAvgPPS) // CHANGED: Call DlogEngine
				if avgPps < float64(rule.MinAvgPPS) {
					DlogEngine("    AvgPPS %.2f less than required %d. Skipping group.", avgPps, rule.MinAvgPPS) // CHANGED: Call DlogEngine
					continue
				}
			} else {
				DlogEngine("    Group duration is zero or negative (%f), cannot calculate AvgPPS. Skipping AvgPPS check.", groupDurationSeconds) // CHANGED: Call DlogEngine
				continue 
			}
		}

		DlogEngine("  Rule '%s' matched for group %v!", rule.Name, k) // CHANGED: Call DlogEngine
		return true, group
	}

	DlogEngine("No group matched for rule '%s'.", rule.Name) // CHANGED: Call DlogEngine
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
		DlogEngine("Unknown TCP flag requirement: %s", required) // CHANGED: Call DlogEngine
		return false
	}
}

func isMyPrefix(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		DlogEngine("Failed to parse IP in isMyPrefix: %s", ipStr) // CHANGED: Call DlogEngine
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

