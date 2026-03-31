package routeros

import (
	"context"
//	"fmt"
	"strconv"
	"strings"
)

// SystemIdentity returns the router's hostname from /rest/system/identity.
func (c *Client) SystemIdentity(ctx context.Context) (string, error) {
	var result map[string]string
	if err := c.get(ctx, "system/identity", nil, &result); err != nil {
		return "", err
	}
	return result["name"], nil
}

// GetRouterInfo returns combined identity + resource information.
func (c *Client) GetRouterInfo(ctx context.Context) (*RouterInfo, error) {
	identity, err := c.SystemIdentity(ctx)
	if err != nil {
		return nil, err
	}
	var res map[string]string
	if err := c.get(ctx, "system/resource", nil, &res); err != nil {
		return &RouterInfo{Identity: identity}, nil
	}
	info := &RouterInfo{
		Identity:  identity,
		Version:   res["version"],
		Platform:  res["platform"],
		BoardName: res["board-name"],
		Uptime:    res["uptime"],
		CPULoad:   parseIntField(res["cpu-load"]),
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(res["free-memory"]), 10, 64); err == nil {
		info.FreeMemory = v
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(res["total-memory"]), 10, 64); err == nil {
		info.TotalMemory = v
	}
	return info, nil
}

// PingHost pings a host via RouterOS REST /rest/tool/ping.
// Runs on the router — measures from router's perspective.
func (c *Client) PingHost(ctx context.Context, host string, count int) PingResult {
	if count <= 0 {
		count = 3
	}
	result := PingResult{Host: host}

	body := map[string]interface{}{
		"address":  host,
		"count":    count,
		"interval": "100ms",
	}
	var raw []map[string]string
	if err := c.post(ctx, "tool/ping", body, &raw); err != nil {
		result.Error = err.Error()
		return result
	}
	if len(raw) == 0 {
		result.Error = "no reply"
		return result
	}
	last := raw[len(raw)-1]
	result.Sent, _ = strconv.Atoi(last["sent"])
	result.Received, _ = strconv.Atoi(last["received"])
	if result.Sent > 0 {
		result.LossPct = float64(result.Sent-result.Received) / float64(result.Sent) * 100
	}
	result.MinRTTms = parseRTT(last["min-rtt"])
	result.AvgRTTms = parseRTT(last["avg-rtt"])
	result.MaxRTTms = parseRTT(last["max-rtt"])
	return result
}

func parseRTT(s string) float64 {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "ms"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		return v
	case strings.HasSuffix(s, "us"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "us"), 64)
		return v / 1000.0
	case strings.HasSuffix(s, "s"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		return v * 1000.0
	default:
		v, _ := strconv.ParseFloat(s, 64)
		return v
	}
}

// UpstreamLabelFromIface strips port prefix: "sfp1-Synapsecom" → "Synapsecom"
func UpstreamLabelFromIface(name string) string {
	if idx := strings.Index(name, "-"); idx != -1 {
		if looksLikePort(name[:idx]) {
			return name[idx+1:]
		}
	}
	return name
}

func looksLikePort(s string) bool {
	for _, p := range []string{"sfp", "ether", "bond", "bridge", "vlan", "ppp", "wlan", "combo"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			return true
		}
	}
	return false
}

// BuildNextHopMap creates gateway-IP → upstream-name map from IP address table.
func BuildNextHopMap(addrs []IPAddress) map[string]string {
	m := make(map[string]string)
	for _, a := range addrs {
		if !a.Disabled {
			m[strings.Split(a.Address, "/")[0]] = UpstreamLabelFromIface(a.Interface)
		}
	}
	return m
}

// UpstreamNameForNextHop resolves a next-hop IP to an upstream name.
func UpstreamNameForNextHop(nextHop string, addrs []IPAddress) string {
	for _, a := range addrs {
		if !a.Disabled && strings.Split(a.Address, "/")[0] == nextHop {
			return UpstreamLabelFromIface(a.Interface)
		}
	}
	return ""
}

// RouterInfo aggregates router metadata.
type RouterInfo struct {
	Identity    string `json:"identity"`
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	BoardName   string `json:"board_name"`
	Uptime      string `json:"uptime"`
	CPULoad     int    `json:"cpu_load"`
	FreeMemory  int64  `json:"free_memory_bytes"`
	TotalMemory int64  `json:"total_memory_bytes"`
}

// SessionSummary holds aggregate BGP session counts.
type SessionSummary struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	Down        int `json:"down"`
}

// StateColor returns a CSS variable name for a session state.
func StateColor(s BGPSessionState) string {
	switch s {
	case StateEstablished:
		return "var(--green)"
	case StateActive, StateConnect, StateOpenSent, StateOpenConfirm:
		return "var(--yellow)"
	default:
		return "var(--red)"
	}
}

