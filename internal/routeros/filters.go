package routeros

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ── Routing filter rules ───────────────────────────────────────────────────────

// ListFilterRules returns all routing filter rules from /routing/filter/rule.
// These explain *why* a route has a certain local-pref or distance:
//
//	if (bgp-as-path 52055) { set bgp-local-pref 150; set distance 30; accept }
//
// Pathfinder can use these to annotate routes with their matching rule.
func (c *Client) ListFilterRules(ctx context.Context) ([]FilterRule, error) {
	reply, err := c.run(ctx, "/routing/filter/rule/print",
		"=.proplist=.id,chain,rule,disabled,comment",
	)
	if err != nil {
		return nil, fmt.Errorf("ListFilterRules: %w", err)
	}

	rules := make([]FilterRule, 0, len(reply.Re))
	for _, s := range reply.Re {
		r := FilterRule{
			ID:       s.Map[".id"],
			Chain:    s.Map["chain"],
			Rule:     s.Map["rule"],
			Disabled: parseBool(s.Map["disabled"]),
			Comment:  s.Map["comment"],
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// MatchingRules returns the subset of rules whose chain or rule text relates
// to the given ASN. Useful for Pathfinder's "why does this route have distance 30?"
// annotation.
func MatchingRules(rules []FilterRule, asn uint32) []FilterRule {
	asnStr := fmt.Sprintf("%d", asn)
	var matched []FilterRule
	for _, r := range rules {
		if strings.Contains(r.Rule, asnStr) || strings.Contains(r.Comment, asnStr) {
			matched = append(matched, r)
		}
	}
	return matched
}

// ── IP Addresses (upstream auto-discovery) ────────────────────────────────────

// ListIPAddresses returns all IP addresses from /ip/address.
// Each entry maps an IP subnet to an interface name, giving us the subnet
// that belongs to each upstream peering link.
//
// This powers Pathfinder's upstream auto-discovery:
//
//	next-hop 195.48.x.x → falls in 195.48.x.0/27 → interface sfp2-GRIX → upstream "GRIX"
func (c *Client) ListIPAddresses(ctx context.Context) ([]IPAddress, error) {
	reply, err := c.run(ctx, "/ip/address/print",
		"=.proplist=.id,address,network,interface,disabled",
	)
	if err != nil {
		return nil, fmt.Errorf("ListIPAddresses: %w", err)
	}

	addrs := make([]IPAddress, 0, len(reply.Re))
	for _, s := range reply.Re {
		a := IPAddress{
			ID:        s.Map[".id"],
			Address:   s.Map["address"], // includes prefix len: "195.48.96.25/27"
			Network:   s.Map["network"], // just the net: "195.48.96.0"
			Interface: s.Map["interface"],
			Disabled:  parseBool(s.Map["disabled"]),
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

// UpstreamNameForNextHop resolves a BGP next-hop IP to the upstream name using
// the IP address table from the router.
//
// The interface name encodes the upstream: "sfp2-GRIX" → "GRIX", "sfp1-Synapsecom" → "Synapsecom".
func UpstreamNameForNextHop(nextHop string, addrs []IPAddress) string {
	nhIP := net.ParseIP(nextHop)
	if nhIP == nil {
		return ""
	}
	for _, a := range addrs {
		if a.Disabled {
			continue
		}
		_, ipNet, err := net.ParseCIDR(a.Address)
		if err != nil {
			continue
		}
		if ipNet.Contains(nhIP) {
			return UpstreamLabelFromIface(a.Interface)
		}
	}
	return ""
}

// UpstreamLabelFromIface strips the port prefix from interface names.
// Exported so pathfinder handlers can use it without a full IPAddress lookup.
//
//	"sfp2-GRIX"       → "GRIX"
//	"sfp1-Synapsecom" → "Synapsecom"
//	"ether1-NetIX"    → "NetIX"
//	"GR-IX"           → "GR-IX"   (no port prefix to strip)
func UpstreamLabelFromIface(name string) string {
	if idx := strings.Index(name, "-"); idx != -1 {
		prefix := name[:idx]
		if looksLikePort(prefix) {
			return name[idx+1:]
		}
	}
	return name
}

func looksLikePort(s string) bool {
	portPrefixes := []string{"sfp", "ether", "bond", "bridge", "vlan", "ppp", "wlan", "combo"}
	sl := strings.ToLower(s)
	for _, p := range portPrefixes {
		if strings.HasPrefix(sl, p) {
			return true
		}
	}
	return false
}

// BuildNextHopMap creates a nextHop-IP → upstreamName map from the IP address table.
func BuildNextHopMap(addrs []IPAddress) map[string]string {
	m := make(map[string]string)
	for _, a := range addrs {
		if a.Disabled {
			continue
		}
		ip := strings.Split(a.Address, "/")[0]
		m[ip] = UpstreamLabelFromIface(a.Interface)
	}
	return m
}
