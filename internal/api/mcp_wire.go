package api

// mcp_wire.go stands up argus's embedded read-only MCP server (internal/mcpserver)
// and mounts it at /mcp behind the existing WithAuth gate. It is the ONLY place
// that knows both the api internals and the mcpserver package, keeping mcpserver
// free of api coupling (no import cycle).
//
// Each tool is a typed closure over the api package's own globals + helpers
// (flowstore queries, buildIPProfileResponse, enrich SNMP, flowlog) — the same
// reads the HTTP endpoints do — so the MCP surface is read-only by construction.

import (
	"context"
	"errors"
	"net/http"

	"argus/internal/config"
	"argus/internal/enrich"
	"argus/internal/flowlog"
	"argus/internal/flowstore"
	"argus/internal/mcpserver"
)

// Version is the argus build version, set by main before Start(); surfaced in the
// MCP initialize result. Defaults to "dev" for local/test builds.
var Version = "dev"

// mcpEnabled reports whether the embedded MCP server should mount. Default ON;
// api.mcp_enabled=false in config disables it.
func mcpEnabled() bool {
	if config.AppConfig != nil && config.AppConfig.API.MCPEnabled != nil {
		return *config.AppConfig.API.MCPEnabled
	}
	return true
}

// registerMCPServer mounts /mcp on mux behind WithAuth, unless disabled by config.
func registerMCPServer(mux *http.ServeMux) {
	if !mcpEnabled() {
		return
	}
	h := mcpserver.New(mcpserver.Deps{
		Version: Version,
		Tools:   mcpTools(),
	})
	// WithAuth = bearer (api.tokens) OR allow_ips OR session — the same gate the
	// rest of the authenticated API uses, and exactly what cfm-web's FleetMcpClient
	// presents (Authorization: Bearer <agent token>).
	mux.HandleFunc("/mcp", WithAuth(h.HTTPHandler().ServeHTTP))
}

// mcpTools builds the read-only tool closures over the api globals.
func mcpTools() mcpserver.Tools {
	return mcpserver.Tools{
		HostTraffic: func(ip string, hours, top int) (any, error) {
			if DB == nil {
				return nil, errors.New("flow DB unavailable")
			}
			since, until := hostWindowHours(hours)
			if top <= 0 {
				top = defaultHostTopN
			}
			return flowstore.QueryLocalHostInsights(DB, ip, since, until, top)
		},
		TopLocalHosts: func(hours, top int) (any, error) {
			if DB == nil {
				return nil, errors.New("flow DB unavailable")
			}
			since, until := hostWindowHours(hours)
			if top <= 0 {
				top = defaultHostsTopN
			}
			hosts, err := flowstore.QueryTopLocalHosts(DB, since, until, top)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"since": since, "until": until, "count": len(hosts),
				"hosts": hosts, "partial": true,
			}, nil
		},
		InfoIP: func(ip string) (any, error) {
			res, _, err := buildIPProfileResponse(context.Background(), ip, false)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
		Interfaces: func() (any, error) {
			if enrich.SNMPClient == nil {
				return nil, errors.New("snmp not configured")
			}
			return enrich.GetInterfaceTraffic(enrich.SNMPClient, enrich.IFNames)
		},
		FlowSearch: func(f mcpserver.FlowQuery) (any, error) {
			lg := flowlog.Global
			if lg == nil {
				return map[string]any{
					"enabled": false,
					"hint":    "set flowlog.enabled: true in config.yaml to capture raw flows",
				}, nil
			}
			filt := flowlog.Filter{
				IP: f.IP, SrcIP: f.SrcIP, DstIP: f.DstIP, Dir: f.Dir,
				Since: f.Since, Until: f.Until, Limit: f.Limit,
			}
			if f.Proto > 0 && f.Proto <= 255 {
				filt.Proto, filt.HasProto = uint8(f.Proto), true
			}
			if f.Port > 0 && f.Port <= 65535 {
				filt.Port, filt.HasPort = uint16(f.Port), true
			}
			rowCount, sizeBytes, _ := lg.Stats()
			flows, err := lg.Query(filt)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"enabled":   true,
				"row_count": rowCount,
				"size_mb":   float64(sizeBytes) / (1 << 20),
				"count":     len(flows),
				"flows":     flows,
			}, nil
		},
	}
}
