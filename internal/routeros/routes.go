package routeros

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ListDetailedRoutesByPrefix queries /routing/route (RouterOS 7 full RIB) for a
// specific prefix. Returns ALL paths — active, candidate, best-candidate — with
// full BGP attributes: AS-path, local-pref, MED, communities, session name.
//
// Unlike /ip/route which only shows the winning route, /routing/route exposes
// every received path and why each was or wasn't selected (contribution field).
func (c *Client) ListDetailedRoutesByPrefix(ctx context.Context, prefix string) ([]Route, error) {
	reply, err := c.run(ctx, "/routing/route/print",
		"=detail=",
		fmt.Sprintf("?.dst-address=%s", prefix),
	)
	if err != nil {
		return nil, fmt.Errorf("ListDetailedRoutesByPrefix %q: %w", prefix, err)
	}

	routes := make([]Route, 0, len(reply.Re))
	for _, s := range reply.Re {
		routes = append(routes, parseDetailedRoute(s.Map))
	}
	return routes, nil
}

// ListRoutes returns routes from /ip/route (forwarding table — winner only).
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
		routes = append(routes, parseRoute(s.Map))
	}
	return routes, nil
}

// ListBGPRoutes returns all BGP-learned routes from /ip/route.
func (c *Client) ListBGPRoutes(ctx context.Context) ([]Route, error) {
	return c.ListRoutes(ctx, "?bgp=yes")
}

// ListRoutesByASN returns all BGP routes whose origin AS matches asn.
func (c *Client) ListRoutesByASN(ctx context.Context, asn uint32) ([]Route, error) {
	all, err := c.ListBGPRoutes(ctx)
	if err != nil {
		return nil, err
	}
	var filtered []Route
	for _, r := range all {
		if r.BGPAttr != nil && r.BGPAttr.OriginAS == asn {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// parseDetailedRoute parses a sentence from /routing/route print detail.
// RouterOS 7 uses dot-notation for BGP sub-fields: bgp.session, bgp.as-path etc.
func parseDetailedRoute(m map[string]string) Route {
	r := Route{
		ID:           m[".id"],
		DstAddress:   m["dst-address"],
		RoutingTable: m["routing-table"],
		Distance:     parseIntField(m["distance"]),
		IsBGP:        true,
	}

	contrib := strings.TrimSpace(m["contribution"])
	r.Active = contrib == "active"

	// immediate-gw: "78.108.36.244%sfp1-Synapsecom" — next-hop and interface in one field
	if igw := strings.TrimSpace(m["immediate-gw"]); igw != "" {
		parts := strings.SplitN(igw, "%", 2)
		r.Gateway = parts[0]
		if len(parts) == 2 {
			r.Interface = parts[1]
		}
	}
	if r.Gateway == "" {
		r.Gateway = strings.TrimSpace(m["gateway"])
	}

	r.BGPAttr = &BGPRouteAttr{
		Origin:       strings.TrimSpace(m["bgp.origin"]),
		LocalPref:    parseIntField(m["bgp.local-pref"]),
		MED:          parseIntField(m["bgp.med"]),
		SessionName:  strings.TrimSpace(m["bgp.session"]),
		BelongsTo:    strings.TrimSpace(m["belongs-to"]),
		Contribution: contrib,
		NextHop:      r.Gateway,
	}

	// AS-path: comma-separated "8280,6762,1241"
	if asp := strings.TrimSpace(m["bgp.as-path"]); asp != "" {
		for _, tok := range strings.FieldsFunc(asp, func(ch rune) bool {
			return ch == ',' || ch == ' '
		}) {
			if tok = strings.TrimSpace(tok); tok == "" {
				continue
			}
			if a, err := strconv.ParseUint(tok, 10, 32); err == nil {
				r.BGPAttr.ASPath = append(r.BGPAttr.ASPath, uint32(a))
			}
		}
		if n := len(r.BGPAttr.ASPath); n > 0 {
			r.BGPAttr.OriginAS = r.BGPAttr.ASPath[n-1]
		}
	}

	// Standard communities: "6762:1,6762:30,6762:40"
	if comms := strings.TrimSpace(m["bgp.communities"]); comms != "" {
		for _, c := range strings.Split(comms, ",") {
			if t := strings.TrimSpace(c); t != "" {
				r.BGPAttr.Communities = append(r.BGPAttr.Communities, t)
			}
		}
	}

	// Large communities: "50745:1000:1,50745:1001:1"
	if lc := strings.TrimSpace(m["bgp.large-communities"]); lc != "" {
		for _, c := range strings.Split(lc, ",") {
			if t := strings.TrimSpace(c); t != "" {
				r.BGPAttr.LargeCommunities = append(r.BGPAttr.LargeCommunities, t)
			}
		}
	}

	return r
}

func parseRoute(m map[string]string) Route {
	r := Route{
		ID:          m[".id"],
		DstAddress:  m["dst-address"],
		RoutingTable: m["routing-table"],
		Distance:    parseIntField(m["distance"]),
		Scope:       parseIntField(m["scope"]),
		TargetScope: parseIntField(m["target-scope"]),
		Active:      parseBool(m["active"]),
		Dynamic:     parseBool(m["dynamic"]),
		IsBGP:       parseBool(m["bgp"]),
		Blackhole:   parseBool(m["blackhole"]),
		ECMP:        parseBool(m["ecmp"]),
	}

	if gw := m["gateway"]; gw != "" {
		r.Gateway = gw
	} else if gwStatus := m["gateway-status"]; gwStatus != "" {
		if parts := strings.Fields(gwStatus); len(parts) > 0 {
			r.Gateway = parts[0]
		}
	}

	if gwStatus := m["gateway-status"]; gwStatus != "" {
		parts := strings.Fields(gwStatus)
		for i, p := range parts {
			if p == "reachable" && i+1 < len(parts) {
				r.Interface = parts[i+1]
				break
			}
		}
	}

	return r
}

func parseBool(s string) bool {
	return s == "true" || s == "yes"
}

func parseIntField(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}
