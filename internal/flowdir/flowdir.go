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

import (
	"fmt"
	"net"
)

// Classifier holds the network's identity: the upstream interface indices and
// the local prefixes. Build one with New / NewWithExporters and reuse it — it
// is read-only after construction and safe for concurrent use.
//
// Interface indices are only unique per router. With more than one NetFlow
// exporter, index 2 on one router is not index 2 on the other, so upstreams
// can be given per exporter IP; an exporter without its own entry uses the
// default list.
type Classifier struct {
	upstreamIfaces map[uint32]bool            // default, for exporters not in byExporter
	byExporter     map[string]map[uint32]bool // exporter IP (canonical form) → its upstreams
	myNets         []*net.IPNet
}

// New builds a Classifier from the raw config lists (one shared upstream list).
func New(upstreamIfaces []uint32, myNets []*net.IPNet) *Classifier {
	return &Classifier{upstreamIfaces: ifaceSet(upstreamIfaces), myNets: myNets}
}

// NewWithExporters is New plus per-exporter upstream lists, keyed by the
// exporter's IP (the source address of its NetFlow packets). An exporter listed
// here — even with an empty list — uses only its own entry.
func NewWithExporters(upstreamIfaces []uint32, byExporter map[string][]uint32, myNets []*net.IPNet) (*Classifier, error) {
	c := New(upstreamIfaces, myNets)
	if len(byExporter) == 0 {
		return c, nil
	}
	c.byExporter = make(map[string]map[uint32]bool, len(byExporter))
	for addr, idxs := range byExporter {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("flowdir: upstream_interfaces_by_exporter: %q is not an IP address", addr)
		}
		c.byExporter[ip.String()] = ifaceSet(idxs)
	}
	return c, nil
}

func ifaceSet(idxs []uint32) map[uint32]bool {
	set := make(map[uint32]bool, len(idxs))
	for _, idx := range idxs {
		set[idx] = true
	}
	return set
}

// upstreamsFor returns the upstream set that applies to flows from exporter
// ("" = unknown exporter → the default list).
func (c *Classifier) upstreamsFor(exporter string) map[uint32]bool {
	if c.byExporter != nil && exporter != "" {
		if set, ok := c.byExporter[canonicalIP(exporter)]; ok {
			return set
		}
	}
	return c.upstreamIfaces
}

func canonicalIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// CountsAsUpstream reports whether interface idx of exporter should be treated
// as an upstream for per-interface accounting: true when it is a configured
// upstream, and also when that exporter has no upstreams configured at all
// (then every interface counts, the historical behaviour).
func (c *Classifier) CountsAsUpstream(exporter string, idx uint32) bool {
	set := c.upstreamsFor(exporter)
	return len(set) == 0 || set[idx]
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

// Classify applies the 3-tier logic. exporter is the IP of the router that
// exported the flow ("" if unknown), inIface / outIface its NetFlow
// INPUT_SNMP / OUTPUT_SNMP indices, srcHost / dstHost the IP strings, and
// flowDirection the raw NetFlow DIRECTION field (MikroTik always sends 0).
func (c *Classifier) Classify(exporter string, inIface, outIface uint32, srcHost, dstHost string, flowDirection uint8) Result {
	// 1. Interface index — most reliable (avoids the MikroTik direction=0 bug).
	if up := c.upstreamsFor(exporter); len(up) > 0 {
		if inIface != 0 && up[inIface] {
			return Result{Inbound: true}
		}
		if outIface != 0 && up[outIface] {
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
