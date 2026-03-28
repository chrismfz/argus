package detection

import (
	"fmt"
	"net"
	"strings"
	"time"
)


func parseCIDRs(cidrs []string) []*net.IPNet {
    var out []*net.IPNet
    for _, c := range cidrs {
        if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
            out = append(out, n)
        }
    }
    return out
}

func ipInAny(ipStr string, nets []*net.IPNet) bool {
    ip := net.ParseIP(ipStr)
    if ip == nil { return false }
    for _, n := range nets {
        if n.Contains(ip) { return true }
    }
    return false
}

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

        // Normalize ports once per rule
        dstPorts := rule.DstPorts()
        srcPorts := rule.SrcPorts()


        onlyNets := parseCIDRs(rule.OnlyPrefixes)
        for _, f := range flows {
		if f.Timestamp.Before(cutoff) {
			DlogEngine("  Flow %s->%s (at %s) is before rule cutoff %s, skipping.", f.SrcIP, f.DstIP, f.Timestamp.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339)) // CHANGED: Call DlogEngine
			continue
		}

                // Per-rule exact excludes
                for _, x := range rule.ExcludeDstIPs {
                        if f.DstIP == x {
                                DlogEngine("  Excluding dst %s per rule.", x)
                                continue
                        }
                }
                for _, x := range rule.ExcludeSrcIPs {
                        if f.SrcIP == x {
                                DlogEngine("  Excluding src %s per rule.", x)
                                continue
                        }
                }
                // Per-rule CIDR scoping (if set, require src OR dst in allowed set)
                if len(onlyNets) > 0 && !(ipInAny(f.SrcIP, onlyNets) || ipInAny(f.DstIP, onlyNets)) {
                        DlogEngine("  Flow %s->%s outside OnlyPrefixes scope. Skipping.", f.SrcIP, f.DstIP)
                        continue
                }

                if rule.Proto != "" && strings.ToLower(rule.Proto) != "any" &&
                   strings.ToLower(f.Proto) != strings.ToLower(rule.Proto) {
			DlogEngine("  Flow %s->%s proto mismatch: expected %s, got %s. Skipping.", f.SrcIP, f.DstIP, rule.Proto, f.Proto) // CHANGED: Call DlogEngine
			continue
		}



                // dst_port filter
                if len(dstPorts) > 0 {
                        ok := false
                        for _, p := range dstPorts { if f.DstPort == p { ok = true; break } }
                        if !ok {
                                DlogEngine("  Flow %s->%s dst port %d not in rule ports %v. Skipping.",
                                        f.SrcIP, f.DstIP, f.DstPort, dstPorts)
                                continue
                        }
                }
                // src_port filter
                if len(srcPorts) > 0 {
                        ok := false
                        for _, p := range srcPorts { if f.SrcPort == p { ok = true; break } }
                        if !ok {
                                DlogEngine("  Flow %s->%s src port %d not in rule ports %v. Skipping.",
                                        f.SrcIP, f.DstIP, f.SrcPort, srcPorts)
                                continue
                        }
                }



		if rule.TCPFlags != "" && !matchTCPFlags(f.TCPFlags, rule.TCPFlags) {
			DlogEngine("  Flow %s->%s TCP flags mismatch: expected %s, got %d. Skipping.", f.SrcIP, f.DstIP, rule.TCPFlags, f.TCPFlags) // CHANGED: Call DlogEngine
			continue
		}






                // Direction gate (explicit, skip internal<->internal)
                if rule.Direction != "" {
                        inMy := func(ip string) bool {
                                dip := net.ParseIP(ip)
                                for _, n := range myNets { if n.Contains(dip) { return true } }
                                return false
                        }
                        switch strings.ToLower(rule.Direction) {
                        case "ingress":

		       if !inMy(f.DstIP) { continue }
		       if inMy(f.SrcIP)  { DlogEngine("  Skipping internal->internal on ingress."); continue }

                        case "egress":

                                if !inMy(f.SrcIP) { continue }
                                if inMy(f.DstIP)  { DlogEngine("  Skipping internal->internal on egress."); continue }
                        }
                }
                // Per-flow floors
                if rule.MinBytes > 0 && f.Bytes < rule.MinBytes {
                        DlogEngine("  Flow %s->%s bytes %d < min_bytes %d. Skipping.", f.SrcIP, f.DstIP, f.Bytes, rule.MinBytes)
                        continue
                }
                if rule.MinPackets > 0 && f.Packets < rule.MinPackets {
                        DlogEngine("  Flow %s->%s packets %d < min_packets %d. Skipping.", f.SrcIP, f.DstIP, f.Packets, rule.MinPackets)
                        continue
                }
                // NAT presence
                if rule.NATPresent {
                        if f.PostNATSrcIP == "" && f.PostNATDstIP == "" && f.PostNATSrcPort == 0 && f.PostNATDstPort == 0 {
                                DlogEngine("  Flow %s->%s has no NAT fields but nat_present=true. Skipping.", f.SrcIP, f.DstIP)
                                continue
                        }
                }
                // TTL gates (only if flow carries values)
                if rule.TTLMin > 0 && f.TTLMin > 0 && f.TTLMin < rule.TTLMin {
                        DlogEngine("  Flow %s->%s TTLMin %d < ttl_min %d. Skipping.", f.SrcIP, f.DstIP, f.TTLMin, rule.TTLMin)
                        continue
                }
                if rule.TTLMax > 0 && f.TTLMax > 0 && f.TTLMax > rule.TTLMax {
                        DlogEngine("  Flow %s->%s TTLMax %d > ttl_max %d. Skipping.", f.SrcIP, f.DstIP, f.TTLMax, rule.TTLMax)
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
                } else if rule.SameSrcIP {
                        k = key{Src: f.SrcIP, Dst: "*"}
                } else if rule.SameSrcPort {
                        k = key{Src: fmt.Sprintf("sport:%d", f.SrcPort), Dst: "*"}
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
                totalBytes := uint64(0)

		// To calculate AvgPPS, use the rule's time window as the duration for the group.
		groupDurationSeconds := window.Seconds()

		for _, f := range group {
			uniquePorts[f.DstPort] = struct{}{}
			uniqueSrcs[f.SrcIP] = struct{}{}
			uniqueDstIPs[f.DstIP] = struct{}{}
			totalPackets += f.Packets
                        totalBytes += f.Bytes
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


                if rule.MinTotalBytes > 0 && totalBytes < rule.MinTotalBytes {
                        DlogEngine("    TotalBytes %d < MinTotalBytes %d. Skipping group.", totalBytes, rule.MinTotalBytes)
                        continue
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

// log reason
func buildReason(rule DetectionRule) string {
	var parts []string


        // dst_port (single ή many)
        if ports := rule.DstPorts(); len(ports) == 1 {
                parts = append(parts, fmt.Sprintf("dst_port=%d", ports[0]))
        } else if len(ports) > 1 {
                parts = append(parts, fmt.Sprintf("dst_port in %v", ports))
        }
        if sps := rule.SrcPorts(); len(sps) == 1 {
                parts = append(parts, fmt.Sprintf("src_port=%d", sps[0]))
        } else if len(sps) > 1 {
                parts = append(parts, fmt.Sprintf("src_port in %v", sps))
        }

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

        if rule.Direction != "" {
               parts = append(parts, fmt.Sprintf("direction=%s", rule.Direction))
        }
        if rule.MinBytes > 0 {
                parts = append(parts, fmt.Sprintf("min_bytes=%d", rule.MinBytes))
        }
        if rule.MinPackets > 0 {
                parts = append(parts, fmt.Sprintf("min_packets=%d", rule.MinPackets))
        }
        if rule.MinTotalBytes > 0 {
                parts = append(parts, fmt.Sprintf("min_total_bytes=%d", rule.MinTotalBytes))
        }
        if rule.NATPresent {
                parts = append(parts, "nat_present=true")
        }
        if rule.TTLMin > 0 {
                parts = append(parts, fmt.Sprintf("ttl_min=%d", rule.TTLMin))
        }
        if rule.TTLMax > 0 {
                parts = append(parts, fmt.Sprintf("ttl_max=%d", rule.TTLMax))
        }

	return strings.Join(parts, ", ")
}

