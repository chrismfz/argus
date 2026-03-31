package routeros

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ListRoutes returns ALL routes from the main routing table — including
// inactive/non-best paths. This is the key advantage over eBGP: RouterOS
// shows every received path with its distance, not just the winner.
//
// Pass filter args to narrow results, e.g.:
//
//	ListRoutes(ctx, "?bgp=yes")            — only BGP routes
//	ListRoutes(ctx, "?routing-table=main") — only main table
func (c *Client) ListRoutes(ctx context.Context, filterArgs ...string) ([]Route, error) {
	args := []string{
		"/ip/route/print",
		"=detail=",
		"=.proplist=.id,dst-address,gateway,gateway-status,routing-table,distance,scope,target-scope,active,dynamic,bgp,blackhole,ecmp",
	}
	args = append(args, filterArgs...)

	reply, err := c.run(ctx, args[0], args[1:]...)
	if err != nil {
		return nil, err
	}

	routes := make([]Route, 0, len(reply.Re))
	for _, s := range reply.Re {
		r := parseRoute(s.Map)
		routes = append(routes, r)
	}
	return routes, nil
}

// ListRoutesByPrefix returns all routes (best + non-best) for a specific prefix.
// This is the core multi-path query: you'll see distance 20 via Synapsecom AND
// distance 30 via GR-IX for the same prefix, unlike GoBGP which only shows best.
func (c *Client) ListRoutesByPrefix(ctx context.Context, prefix string) ([]Route, error) {
	return c.ListRoutes(ctx,
		fmt.Sprintf("?dst-address=%s", prefix),
	)
}

// ListBGPRoutes returns all BGP-learned routes, enriched with BGP attributes
// from /routing/bgp/advertisements where available.
func (c *Client) ListBGPRoutes(ctx context.Context) ([]Route, error) {
	return c.ListRoutes(ctx, "?bgp=yes")
}

// ListRoutesByASN returns all routes whose origin AS matches the given ASN.
// Since RouterOS /ip/route doesn't directly filter by origin ASN, this
// fetches all BGP routes and filters client-side using the AS-path.
//
// For large tables this is acceptable at startup / on-demand; ROUTEWATCH
// should cache results rather than polling continuously.
func (c *Client) ListRoutesByASN(ctx context.Context, asn uint32) ([]Route, error) {
	// Get BGP advertisements which include full attribute detail
	routes, err := c.listBGPAdvertisements(ctx)
	if err != nil {
		// Fall back to basic route list if BGP advertisement table is unavailable
		all, rerr := c.ListBGPRoutes(ctx)
		if rerr != nil {
			return nil, fmt.Errorf("ListRoutesByASN: advertisements failed (%v), routes fallback also failed: %w", err, rerr)
		}
		filtered := all[:0]
		for _, r := range all {
			if r.BGPAttr != nil && r.BGPAttr.OriginAS == asn {
				filtered = append(filtered, r)
			}
		}
		return filtered, nil
	}

	filtered := routes[:0]
	for _, r := range routes {
		if r.BGPAttr != nil && r.BGPAttr.OriginAS == asn {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// listBGPAdvertisements queries /routing/bgp/advertisements which provides
// per-route BGP attributes (local-pref, AS-path, communities, MED).
// This is RouterOS 7 only.
func (c *Client) listBGPAdvertisements(ctx context.Context) ([]Route, error) {
	reply, err := c.run(ctx, "/routing/bgp/advertisements/print",
		"=.proplist=.id,dst-address,gateway,local-pref,med,origin,as-path,communities,nexthop",
	)
	if err != nil {
		return nil, err
	}

	routes := make([]Route, 0, len(reply.Re))
	for _, s := range reply.Re {
		r := Route{
			ID:         s.Map[".id"],
			DstAddress: s.Map["dst-address"],
			Gateway:    s.Map["nexthop"],
			IsBGP:      true,
			BGPAttr:    parseBGPAttr(s.Map),
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

func parseRoute(m map[string]string) Route {
	r := Route{
		ID:           m[".id"],
		DstAddress:   m["dst-address"],
		RoutingTable: m["routing-table"],
	}

	// Gateway and outgoing interface may be combined in "gateway-status"
	// e.g. "78.108.36.244 reachable sfp1-Synapsecom"
	gw := m["gateway"]
	gwStatus := m["gateway-status"]
	if gw != "" {
		r.Gateway = gw
	} else if gwStatus != "" {
		// extract first token
		parts := strings.Fields(gwStatus)
		if len(parts) > 0 {
			r.Gateway = parts[0]
		}
	}

	// Extract interface from gateway-status if present
	// format: "IP reachable INTERFACE"
	if gwStatus != "" {
		parts := strings.Fields(gwStatus)
		for i, p := range parts {
			if p == "reachable" && i+1 < len(parts) {
				r.Interface = parts[i+1]
				break
			}
		}
	}

	r.Distance, _ = strconv.Atoi(m["distance"])
	r.Scope, _ = strconv.Atoi(m["scope"])
	r.TargetScope, _ = strconv.Atoi(m["target-scope"])

	r.Active = parseBool(m["active"])
	r.Dynamic = parseBool(m["dynamic"])
	r.IsBGP = parseBool(m["bgp"])
	r.Blackhole = parseBool(m["blackhole"])
	r.ECMP = parseBool(m["ecmp"])

	return r
}

func parseBGPAttr(m map[string]string) *BGPRouteAttr {
	attr := &BGPRouteAttr{
		Origin:  m["origin"],
		NextHop: m["nexthop"],
	}
	attr.LocalPref, _ = strconv.Atoi(m["local-pref"])
	attr.MED, _ = strconv.Atoi(m["med"])

	// AS-path: RouterOS returns it as space-separated ASNs e.g. "216285 8280 6762 1241"
	if asp := strings.TrimSpace(m["as-path"]); asp != "" {
		for _, tok := range strings.Fields(asp) {
			var a uint32
			if _, err := fmt.Sscanf(tok, "%d", &a); err == nil {
				attr.ASPath = append(attr.ASPath, a)
			}
		}
		if len(attr.ASPath) > 0 {
			attr.OriginAS = attr.ASPath[len(attr.ASPath)-1]
		}
	}

	// Communities: RouterOS returns them comma or space separated
	if comms := strings.TrimSpace(m["communities"]); comms != "" {
		for _, c := range strings.FieldsFunc(comms, func(r rune) bool { return r == ',' || r == ' ' }) {
			c = strings.TrimSpace(c)
			if c != "" {
				attr.Communities = append(attr.Communities, c)
			}
		}
	}

	return attr
}

func parseBool(s string) bool {
	return s == "true" || s == "yes"
}

// PrefixContains checks whether ip falls inside the given CIDR prefix.
// Helper for upstream auto-discovery (next-hop IP in subnet → interface name).
func PrefixContains(prefix, ip string) bool {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return ipNet.Contains(parsed)
}
