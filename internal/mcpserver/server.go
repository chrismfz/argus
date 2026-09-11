// Package mcpserver embeds a small, read-only Model Context Protocol (MCP)
// server inside argus. It exposes argus's own flow telemetry — per-local-host
// traffic, top talkers, IP enrichment, live SNMP interface stats and the raw
// flow log — as MCP tools so an operator can ask argus the "what is this
// traffic" questions from the same place they already query the CFM fleet.
//
// Design (mirrors the CFM daemon's mcpserver so it is drop-in for cfm-web's
// FleetMcpClient / node_call proxy — see docs/ip-insights-and-traffic-anomaly-mcp.md):
//   - Transport is the go-sdk streamable-HTTP handler in STATELESS + JSON mode
//     (plain POST→JSON, no SSE session), robust behind a reverse proxy.
//   - Tools never reach into argus internals directly; each calls a typed
//     closure the api package injects via Deps, keeping this package decoupled
//     (no import cycle with internal/api) and unit-testable with fakes.
//   - Auth is NOT handled here: the api package mounts the returned handler
//     behind its existing WithAuth (bearer token from api.tokens, or allow_ips),
//     the same gate every other authenticated argus endpoint uses.
//
// Read-only by construction: the tool set only reads, and there is no dispatch
// path that could mutate state.
package mcpserver

import (
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tools is the set of typed data closures the api package injects. Each returns
// a JSON-serialisable value (or an error surfaced to the model as a tool error).
// A nil closure means that tool is not registered (e.g. flow_search when the
// raw flow log is disabled).
type Tools struct {
	// HostTraffic: per-local-host in/out series + top peers/ASNs/ports/countries.
	HostTraffic func(ip string, hours, top int) (any, error)
	// TopLocalHosts: our busiest local hosts by bytes over the window.
	TopLocalHosts func(hours, top int) (any, error)
	// InfoIP: GeoIP/ASN/PTR/BGP-path enrichment for any IP.
	InfoIP func(ip string) (any, error)
	// Interfaces: live per-interface throughput via SNMP.
	Interfaces func() (any, error)
	// FlowSearch: raw 5-tuple flow-log query (nil when flowlog is disabled).
	FlowSearch func(f FlowQuery) (any, error)
}

// FlowQuery mirrors the flow-log filter in primitives, so this package need not
// import internal/flowlog. Empty/zero fields are ignored by the closure.
type FlowQuery struct {
	IP    string
	SrcIP string
	DstIP string
	Proto int
	Port  int
	Dir   string
	Since int64
	Until int64
	Limit int
}

// Deps is everything the api package injects to stand the server up.
type Deps struct {
	Version string
	Tools   Tools
}

// Handler wraps the go-sdk streamable MCP handler. Mount HTTPHandler() at /mcp
// behind the api package's auth middleware.
type Handler struct {
	http http.Handler
}

// statelessMCP configures the go-sdk streamable transport the same way the CFM
// daemon does. DisableLocalhostProtection is required because argus sits behind
// an nginx reverse proxy on loopback while the public Host header differs, which
// otherwise trips the SDK's DNS-rebinding guard (403). Auth is the api package's
// WithAuth gate, not Host/loopback, so disabling the guard is safe here.
var statelessMCP = &mcp.StreamableHTTPOptions{
	Stateless:                  true,
	JSONResponse:               true,
	DisableLocalhostProtection: true,
}

// New builds the MCP handler from deps.
func New(deps Deps) *Handler {
	if deps.Version == "" {
		deps.Version = "dev"
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "argus-mcp",
		Title:   "argus flow telemetry (read-only)",
		Version: deps.Version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
		HasTools:     true,
	})
	registerTools(srv, deps.Tools)

	return &Handler{
		http: mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return srv }, statelessMCP),
	}
}

// HTTPHandler returns the raw streamable MCP handler for mounting at /mcp.
func (h *Handler) HTTPHandler() http.Handler { return h.http }

// ── result helpers ──────────────────────────────────────────────────────────

func textResult(b []byte) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

// jsonResult marshals v and returns it as an MCP text result.
func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return textResult(b), nil, nil
}

// instructions is the server-level guidance the MCP client shows the model.
const instructions = `argus NetFlow/IPFIX telemetry, READ-ONLY. These tools answer "what is one of
MY hosts sending/receiving, to whom, and on what port" — the flow-level
attribution a bandwidth spike on an interface graph (LibreNMS/SNMP) raises but
can't itself answer. They only read; nothing here blackholes or changes config.

Orientation:
- host_traffic(ip=<a my_prefixes IP>): that host's in/out byte series over time
  plus its top remote peers / ASNs / ports / countries. Start here when an
  interface graph shows an unexplained spike on a known host.
- top_local_talkers: our busiest local hosts by bytes right now — "which of my
  servers is hot".
- infoip(ip): GeoIP / ASN / PTR / BGP AS-path for any address (local or remote).
- interfaces: live per-interface throughput via SNMP (the LibreNMS-equivalent).
- flow_search: raw 5-tuple flow-log lookup ("what did X do at 03:00") — only
  when the optional flow log is enabled.

host_traffic / top_local_talkers are derived from the per-ASN top-N detail
(dominant peers/ports, not billing-grade totals) and served-egress rows carry
the client's ephemeral port — read a port row's "in" side for the service port.`
