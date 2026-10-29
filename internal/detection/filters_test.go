package detection

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestEvaluateRuleEgressUniqueDstIPs(t *testing.T) {
	_, myNet, _ := net.ParseCIDR("84.54.49.0/24")
	myNets := []*net.IPNet{myNet}
	rule := DetectionRule{
		Name:         "smtp_egress_fanout",
		Proto:        "tcp",
		Direction:    "egress",
		DstPort:      25,
		SameSrcIP:    true,
		UniqueDstIPs: 30,
		MinFlows:     40,
		TimeWindow:   "60s",
	}
	now := time.Now().UTC()
	var flows []Flow
	// One of our hosts talking SMTP to 40 different remote MXs…
	for i := 0; i < 40; i++ {
		flows = append(flows, Flow{
			Timestamp: now, SrcIP: "84.54.49.205", DstIP: fmt.Sprintf("203.0.113.%d", i+1),
			SrcPort: uint16(40000 + i), DstPort: 25, Proto: "tcp",
		})
	}
	// …plus noise the rule must ignore: inbound SMTP and another port.
	flows = append(flows,
		Flow{Timestamp: now, SrcIP: "198.51.100.1", DstIP: "84.54.49.205", DstPort: 25, Proto: "tcp"},
		Flow{Timestamp: now, SrcIP: "84.54.49.205", DstIP: "198.51.100.2", DstPort: 443, Proto: "tcp"},
	)

	matched, group := evaluateRule(rule, flows, myNets)
	if !matched {
		t.Fatal("egress rule with unique_dst_ips did not match 40 MXs from one host")
	}
	if len(group) != 40 || group[0].SrcIP != "84.54.49.205" {
		t.Fatalf("matched group: %d flows from %s; want 40 from 84.54.49.205", len(group), group[0].SrcIP)
	}

	// Below the threshold: 20 distinct MXs.
	if matched, _ := evaluateRule(rule, flows[:20], myNets); matched {
		t.Fatal("matched with only 20 distinct destinations")
	}

	// Ingress rules keep requiring a local destination.
	ingress := DetectionRule{Name: "in", Proto: "tcp", Direction: "ingress", UniqueDstIPs: 1, MinFlows: 1, TimeWindow: "60s"}
	if matched, _ := evaluateRule(ingress, flows[:40], myNets); matched {
		t.Fatal("ingress rule matched outbound flows")
	}
}
