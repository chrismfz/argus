package routeros

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ListDetailedRoutesByPrefix queries /rest/routing/route filtered by dst-address.
// Returns all paths (active, candidate, best-candidate) with full BGP attributes.
// Fast — filter runs on the router side, same speed as the console (~1-2s).
func (c *Client) ListDetailedRoutesByPrefix(ctx context.Context, prefix string) ([]Route, error) {
	var raw []map[string]string
	q := url.Values{"dst-address": {prefix}}
	if err := c.get(ctx, "routing/route", q, &raw); err != nil {
		return nil, fmt.Errorf("ListDetailedRoutesByPrefix %q: %w", prefix, err)
	}
	routes := make([]Route, 0, len(raw))
	for _, m := range raw {
		routes = append(routes, parseDetailedRoute(m))
	}
	return routes, nil
}

// ListBGPRoutes returns all BGP-learned routes from /rest/ip/route.
func (c *Client) ListBGPRoutes(ctx context.Context) ([]Route, error) {
	var raw []map[string]string
	q := url.Values{"bgp": {"true"}}
	if err := c.get(ctx, "ip/route", q, &raw); err != nil {
		return nil, fmt.Errorf("ListBGPRoutes: %w", err)
	}
	routes := make([]Route, 0, len(raw))
	for _, m := range raw {
		routes = append(routes, parseRoute(m))
	}
	return routes, nil
}

// ListIPAddresses returns all IP addresses from /rest/ip/address.
// Used for upstream auto-discovery: next-hop IP → subnet → interface → upstream name.
func (c *Client) ListIPAddresses(ctx context.Context) ([]IPAddress, error) {
	var raw []map[string]string
	if err := c.get(ctx, "ip/address", nil, &raw); err != nil {
		return nil, fmt.Errorf("ListIPAddresses: %w", err)
	}
	addrs := make([]IPAddress, 0, len(raw))
	for _, m := range raw {
		addrs = append(addrs, IPAddress{
			ID:        m[".id"],
			Address:   m["address"],
			Network:   m["network"],
			Interface: m["interface"],
			Disabled:  parseBool(m["disabled"]),
		})
	}
	return addrs, nil
}

// ListNextHops returns the nexthop resolution table from /rest/routing/nexthop.
func (c *Client) ListNextHops(ctx context.Context) ([]NextHop, error) {
	var raw []map[string]string
	if err := c.get(ctx, "routing/nexthop", nil, &raw); err != nil {
		return nil, fmt.Errorf("ListNextHops: %w", err)
	}
	hops := make([]NextHop, 0, len(raw))
	for _, m := range raw {
		hops = append(hops, NextHop{
			ID:        m[".id"],
			Gateway:   m["gateway"],
			Interface: m["interface"],
			Resolved:  parseBool(m["resolved"]),
			Immediate: m["immediate-gw"],
		})
	}
	return hops, nil
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// parseDetailedRoute parses a map from /rest/routing/route.
// The REST API returns the same field names as the binary API detail output.
func parseDetailedRoute(m map[string]string) Route {
	r := Route{
		ID:           m[".id"],
		DstAddress:   m["dst-address"],
		RoutingTable: m["routing-table"],
		Distance:     parseIntField(m["distance"]),
		IsBGP:        parseBool(m["bgp"]),
	}

	contrib := strings.TrimSpace(m["contribution"])
	r.Active = contrib == "active"

	// immediate-gw: "78.108.36.244%sfp1-Synapsecom"
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

	// AS-path: "8280,6762,1241"
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

	// Communities: "6762:1,6762:30,6762:40"
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
		Active:      parseBool(m["active"]),
		Dynamic:     parseBool(m["dynamic"]),
		IsBGP:       parseBool(m["bgp"]),
		Blackhole:   parseBool(m["blackhole"]),
		ECMP:        parseBool(m["ecmp"]),
	}
	if gw := m["gateway"]; gw != "" {
		r.Gateway = gw
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



// TracerouteHop is one hop from /rest/tool/traceroute.
type TracerouteHop struct {
    Hop     int     `json:"hop"`
    Address string  `json:"address"`
    AvgMs   float64 `json:"avg_ms"`
    BestMs  float64 `json:"best_ms"`
    WorstMs float64 `json:"worst_ms"`
    Loss    int     `json:"loss"`
    Status  string  `json:"status,omitempty"` // MPLS labels etc.
}


func (c *Client) Traceroute(ctx context.Context, address, srcAddress string) ([]TracerouteHop, error) {
    body := map[string]interface{}{
        "address":  address,
        "count":    "3",     // 3 probes per hop
        "max-hops": "15",
        "protocol": "icmp",
        "use-dns":  "no",
        // no duration — let count control it
    }
    if srcAddress != "" {
        body["src-address"] = srcAddress
    }

    var raw []map[string]string
    if err := c.postSlow(ctx, "tool/traceroute", body, &raw); err != nil {
        return nil, fmt.Errorf("Traceroute: %w", err)
    }

// Each unique IP appears once — take first occurrence of each address in order.
    // RouterOS REST returns multiple rows per hop (one per probe), all with the
    // same .section value, so section-based grouping doesn't give us hop numbers.
    seen := make(map[string]bool)
    hops := make([]TracerouteHop, 0)
    hopNum := 1
    for _, m := range raw {
        addr := strings.TrimSpace(m["address"])
        avgStr := strings.TrimSpace(m["avg"])
        if addr == "" || avgStr == "" {
            continue
        }
        if seen[addr] {
            continue
        }
        seen[addr] = true
        h := TracerouteHop{
            Hop:     hopNum,
            Address: addr,
            Loss:    parseIntField(m["loss"]),
            Status:  strings.TrimSpace(m["status"]),
        }
        h.AvgMs, _ = strconv.ParseFloat(avgStr, 64)
        h.BestMs, _ = strconv.ParseFloat(strings.TrimSpace(m["best"]), 64)
        h.WorstMs, _ = strconv.ParseFloat(strings.TrimSpace(m["worst"]), 64)
        hops = append(hops, h)
        hopNum++
    }
    return hops, nil
}

