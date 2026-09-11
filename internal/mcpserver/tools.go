package mcpserver

// tools.go registers the read-only MCP tool set. Each tool validates/normalises
// its args and calls the matching typed closure from Deps.Tools; the closure
// (injected by internal/api) does the actual read against flowstore / enrich /
// flowlog / snmp. Keep this list and docs/ip-insights-and-traffic-anomaly-mcp.md
// in sync.

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptrTrue()}

func ptrTrue() *bool { b := true; return &b }

type emptyInput struct{}

func errRequired(field string) error { return fmt.Errorf("%s is required", field) }

// registerTools wires the tool set onto srv. A nil closure skips its tool, so a
// deployment without the raw flow log simply doesn't advertise flow_search.
func registerTools(srv *mcp.Server, t Tools) {
	if t.HostTraffic != nil {
		registerHostTraffic(srv, t)
	}
	if t.TopLocalHosts != nil {
		registerTopLocalTalkers(srv, t)
	}
	if t.InfoIP != nil {
		registerInfoIP(srv, t)
	}
	if t.Interfaces != nil {
		registerInterfaces(srv, t)
	}
	if t.FlowSearch != nil {
		registerFlowSearch(srv, t)
	}
}

// ── host_traffic ──────────────────────────────────────────────────────────────

type hostTrafficInput struct {
	IP    string `json:"ip" jsonschema:"one of YOUR hosts (a my_prefixes address), e.g. 84.54.49.202"`
	Hours int    `json:"hours,omitempty" jsonschema:"look-back window in hours; default 24, max 168 (7d detail retention)"`
	Top   int    `json:"top,omitempty" jsonschema:"how many entries per ranked list (peers/ASNs/ports/countries); default 15"`
}

func registerHostTraffic(srv *mcp.Server, t Tools) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "host_traffic",
		Description: "Per-local-host traffic profile: for one of YOUR hosts (a my_prefixes IP), the in/out byte series over the window plus its top remote peers, ASNs, destination ports and countries — the flow-level answer to an interface-graph spike. Derived from the per-ASN top-N detail (dominant peers/ports, not billing-grade totals); for traffic your host SERVES, a port row's out side is the client's ephemeral port, so read its in side for the service port.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in hostTrafficInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(in.IP) == "" {
			return nil, nil, errRequired("ip")
		}
		v, err := t.HostTraffic(strings.TrimSpace(in.IP), in.Hours, in.Top)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(v)
	})
}

// ── top_local_talkers ─────────────────────────────────────────────────────────

type topLocalInput struct {
	Hours int `json:"hours,omitempty" jsonschema:"look-back window in hours; default 24, max 168"`
	Top   int `json:"top,omitempty" jsonschema:"max local hosts to return; default 25"`
}

func registerTopLocalTalkers(srv *mcp.Server, t Tools) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "top_local_talkers",
		Description: "Our busiest local hosts by total bytes over the window (in/out split) — 'which of my servers is hot right now'. Derived from the per-ASN top-N detail (dominant hosts, not billing-grade totals). Drill into any row with host_traffic(ip=...).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in topLocalInput) (*mcp.CallToolResult, any, error) {
		v, err := t.TopLocalHosts(in.Hours, in.Top)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(v)
	})
}

// ── infoip ────────────────────────────────────────────────────────────────────

type infoIPInput struct {
	IP string `json:"ip" jsonschema:"any IPv4/IPv6 address (local or remote) to enrich"`
}

func registerInfoIP(srv *mcp.Server, t Tools) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "infoip",
		Description: "Enrichment for any IP: GeoIP country, ASN + name, PTR/rDNS, and the BGP AS-path/prefix argus sees for it from the router's RIB. Use to identify a peer surfaced by host_traffic or an address from an interface graph.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in infoIPInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(in.IP) == "" {
			return nil, nil, errRequired("ip")
		}
		v, err := t.InfoIP(strings.TrimSpace(in.IP))
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(v)
	})
}

// ── interfaces ────────────────────────────────────────────────────────────────

func registerInterfaces(srv *mcp.Server, t Tools) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "interfaces",
		Description: "Live per-interface throughput read via SNMP from the router (the LibreNMS-equivalent, in one call): the in/out rates per named interface (e.g. sfp1-Synapsecom, sfp2-GRIX). Use to confirm a spike is real and on which upstream before drilling into host_traffic.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		v, err := t.Interfaces()
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(v)
	})
}

// ── flow_search ───────────────────────────────────────────────────────────────

type flowSearchInput struct {
	IP    string `json:"ip,omitempty" jsonschema:"match either side (src OR dst) of the flow"`
	SrcIP string `json:"src_ip,omitempty" jsonschema:"match the source IP only"`
	DstIP string `json:"dst_ip,omitempty" jsonschema:"match the destination IP only"`
	Proto int    `json:"proto,omitempty" jsonschema:"IP protocol number (6=TCP, 17=UDP, 1=ICMP)"`
	Port  int    `json:"port,omitempty" jsonschema:"match the destination port"`
	Dir   string `json:"dir,omitempty" jsonschema:"direction: in or out"`
	Since int64  `json:"since,omitempty" jsonschema:"unix seconds, inclusive lower bound"`
	Until int64  `json:"until,omitempty" jsonschema:"unix seconds, inclusive upper bound"`
	Limit int    `json:"limit,omitempty" jsonschema:"max rows, newest first; default 200"`
}

func registerFlowSearch(srv *mcp.Server, t Tools) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "flow_search",
		Description: "Raw 5-tuple flow-log lookup — the forensic 'what did X do at 03:00' view (bytes/packets, src/dst IP+port, proto, interfaces, ASNs, direction), newest first. Only available when the optional size-capped flow log is enabled; otherwise it reports how to turn it on.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in flowSearchInput) (*mcp.CallToolResult, any, error) {
		v, err := t.FlowSearch(FlowQuery{
			IP: strings.TrimSpace(in.IP), SrcIP: strings.TrimSpace(in.SrcIP), DstIP: strings.TrimSpace(in.DstIP),
			Proto: in.Proto, Port: in.Port, Dir: strings.TrimSpace(in.Dir),
			Since: in.Since, Until: in.Until, Limit: in.Limit,
		})
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(v)
	})
}
