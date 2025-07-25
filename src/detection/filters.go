package detection

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// dlogEngine is assumed to be available from engine.go as this file is part of the same package.

// 🔎 Ελέγχει αν ένας rule ταιριάζει με πρόσφατα flows
func evaluateRule(rule DetectionRule, flows []Flow, myNets []*net.IPNet) (bool, []Flow) {
	now := time.Now()
	window, err := time.ParseDuration(rule.TimeWindow)
	if err != nil {
		dlogEngine("Invalid TimeWindow for rule %s: %v", rule.Name, err)
		return false, nil // invalid rule
	}
	cutoff := now.Add(-window)
	dlogEngine("Evaluating rule '%s' with %d flows. TimeWindow: %s, Cutoff: %s", rule.Name, len(flows), rule.TimeWindow, cutoff.Format(time.RFC3339))


	type key struct {
		Src string
		Dst string
	}
	groups := make(map[key][]Flow)

	for _, f := range flows {
		if f.Timestamp.Before(cutoff) {
			dlogEngine("  Flow %s->%s (at %s) is before rule cutoff %s, skipping.", f.SrcIP, f.DstIP, f.Timestamp.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339))
			continue
		}
		if rule.Proto != "" && strings.ToLower(f.Proto) != strings.ToLower(rule.Proto) {
			dlogEngine("  Flow %s->%s proto mismatch: expected %s, got %s. Skipping.", f.SrcIP, f.DstIP, rule.Proto, f.Proto)
			continue
		}
		if rule.DstPort != 0 && f.DstPort != rule.DstPort {
			dlogEngine("  Flow %s->%s dst port mismatch: expected %d, got %d. Skipping.", f.SrcIP, f.DstIP, rule.DstPort, f.DstPort)
			continue
		}
		if rule.TCPFlags != "" && !matchTCPFlags(f.TCPFlags, rule.TCPFlags) {
			dlogEngine("  Flow %s->%s TCP flags mismatch: expected %s, got %d. Skipping.", f.SrcIP, f.DstIP, rule.TCPFlags, f.TCPFlags)
			continue
		}
		// This condition applies if any of the SameDstIP, SameDstPort, MinUniqueSrcIPs, UniqueDstIPs are relevant
		// For test_all_tcp, none of these are true, so this check will be skipped.
		if (rule.SameDstIP || rule.SameDstPort || rule.MinUniqueSrcIPs > 0 || rule.UniqueDstIPs > 0) && !isMyPrefix(f.DstIP, myNets) {
			dlogEngine("  Flow %s->%s DstIP %s is not in myNets, and rule requires local destination. Skipping.", f.SrcIP, f.DstIP, f.DstIP)
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
		dlogEngine("  Flow %s->%s added to group %v. Group size: %d", f.SrcIP, f.DstIP, k, len(groups[k]))
	}

	if len(groups) == 0 {
		dlogEngine("No groups formed for rule '%s'.", rule.Name)
		return false, nil
	}

	for k, group := range groups {
		dlogEngine("  Evaluating group %v for rule '%s' with %d flows.", k, rule.Name, len(group))

		if len(group) < rule.MinFlows {
			dlogEngine("    Group size %d less than MinFlows %d. Skipping group.", len(group), rule.MinFlows)
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
			dlogEngine("    Unique DstPorts %d less than required %d. Skipping group.", len(uniquePorts), rule.UniqueDstPorts)
			continue
		}

		if rule.MinUniqueSrcIPs > 0 && len(uniqueSrcs) < rule.MinUniqueSrcIPs {
			dlogEngine("    Unique SrcIPs %d less than required %d. Skipping group.", len(uniqueSrcs), rule.MinUniqueSrcIPs)
			continue
		}

		if rule.UniqueDstIPs > 0 && len(uniqueDstIPs) < rule.UniqueDstIPs { 
			dlogEngine("    Unique DstIPs %d less than required %d. Skipping group.", len(uniqueDstIPs), rule.UniqueDstIPs)
			continue
		}

		if rule.MinAvgPPS > 0 {
			if groupDurationSeconds > 0 {
				avgPps := float64(totalPackets) / groupDurationSeconds
				dlogEngine("    Calculated AvgPPS: %.2f (Total Packets: %d, Duration: %.2f s). Required MinAvgPPS: %d", avgPps, totalPackets, groupDurationSeconds, rule.MinAvgPPS)
				if avgPps < float64(rule.MinAvgPPS) {
					dlogEngine("    AvgPPS %.2f less than required %d. Skipping group.", avgPps, rule.MinAvgPPS)
					continue
				}
			} else {
				dlogEngine("    Group duration is zero or negative (%f), cannot calculate AvgPPS. Skipping AvgPPS check.", groupDurationSeconds)
				continue 
			}
		}

		dlogEngine("  Rule '%s' matched for group %v!", rule.Name, k)
		return true, group
	}

	dlogEngine("No group matched for rule '%s'.", rule.Name)
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
		dlogEngine("Unknown TCP flag requirement: %s", required)
		return false
	}
}

func isMyPrefix(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		dlogEngine("Failed to parse IP in isMyPrefix: %s", ipStr)
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

