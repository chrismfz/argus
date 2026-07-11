// Package flowdir centralises argus's flow direction classification — the
// 3-tier logic that decides whether a flow is inbound or outbound:
//
//  1. upstream interface index (INPUT_SNMP / OUTPUT_SNMP matched against the
//     configured upstream interfaces) — the most reliable signal, and the one
//     that works around MikroTik always sending NetFlow DIRECTION=0;
//  2. IP prefix matching against the local prefixes (my_prefixes);
//  3. the raw NetFlow DIRECTION field, as a last resort.
//
// This logic was previously duplicated in telemetry.classifyDirection and
// flowstore.classifyInbound, which had to be kept in sync by hand. Both now
// delegate here so the two can never drift apart. See CLAUDE.md rule 7
// ("direction classification is sacred").
package flowdir

import "net"

// Classifier holds the network's identity: the set of upstream interface
// indices and the local prefixes. Build one with New and reuse it — it is
// read-only after construction and safe for concurrent use.
type Classifier struct {
	upstreamIfaces map[uint32]bool
	myNets         []*net.IPNet
}

// New builds a Classifier from the raw config lists.
func New(upstreamIfaces []uint32, myNets []*net.IPNet) *Classifier {
	ifSet := make(map[uint32]bool, len(upstreamIfaces))
	for _, idx := range upstreamIfaces {
		ifSet[idx] = true
	}
	return &Classifier{upstreamIfaces: ifSet, myNets: myNets}
}

// Result is the full classification outcome.
type Result struct {
	// Inbound is true when the flow is coming into our network.
	Inbound bool
	// SrcInMy / DstInMy report whether the src / dst IP fell inside myNets.
	// They are only meaningful when tier 2 (prefix matching) is reached; when
	// tier 1 (interface index) decides, both are false.
	SrcInMy bool
	DstInMy bool
}

// Classify applies the 3-tier logic. inIface / outIface are the NetFlow
// INPUT_SNMP / OUTPUT_SNMP indices, srcHost / dstHost the IP strings, and
// flowDirection the raw NetFlow DIRECTION field (MikroTik always sends 0).
func (c *Classifier) Classify(inIface, outIface uint32, srcHost, dstHost string, flowDirection uint8) Result {
	// 1. Interface index — most reliable (avoids the MikroTik direction=0 bug).
	if len(c.upstreamIfaces) > 0 {
		if inIface != 0 && c.upstreamIfaces[inIface] {
			return Result{Inbound: true}
		}
		if outIface != 0 && c.upstreamIfaces[outIface] {
			return Result{Inbound: false}
		}
	}

	// 2. IP prefix matching.
	var res Result
	if len(c.myNets) > 0 {
		res.DstInMy = c.IsMyIP(dstHost)
		res.SrcInMy = c.IsMyIP(srcHost)
		if res.DstInMy {
			res.Inbound = true
			return res
		}
		if res.SrcInMy {
			res.Inbound = false
			return res
		}
	}

	// 3. NetFlow DIRECTION fallback.
	res.Inbound = flowDirection == 0
	return res
}

// IsMyIP reports whether ip falls inside any of the local prefixes.
func (c *Classifier) IsMyIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range c.myNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
