package routeros

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// PingHost pings a host via RouterOS /ping API and returns RTT statistics.
// The ping is executed on the router itself, so it measures the path from
// the router's perspective — which is exactly what you want for next-hop RTT.
//
// count is the number of pings to send (3 is a good default).
// RouterOS sends one reply sentence per ping, then a final !done.
func (c *Client) PingHost(ctx context.Context, host string, count int) PingResult {
	if count <= 0 {
		count = 3
	}

	result := PingResult{Host: host}

	reply, err := c.run(ctx, "/ping",
		fmt.Sprintf("=address=%s", host),
		fmt.Sprintf("=count=%d", count),
		"=interval=100ms",
	)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// RouterOS returns one sentence per ping reply. The last sentence has
	// cumulative stats. We use the final sentence.
	if len(reply.Re) == 0 {
		result.Error = "no ping reply"
		return result
	}

	// Parse the last sentence which has final cumulative stats
	last := reply.Re[len(reply.Re)-1].Map

	result.Sent, _ = strconv.Atoi(strings.TrimSpace(last["sent"]))
	result.Received, _ = strconv.Atoi(strings.TrimSpace(last["received"]))

	if result.Sent > 0 {
		result.LossPct = float64(result.Sent-result.Received) / float64(result.Sent) * 100
	}

	// RTT fields come as "2ms", "4ms" etc. — strip the unit
	result.MinRTTms = parseRTT(last["min-rtt"])
	result.AvgRTTms = parseRTT(last["avg-rtt"])
	result.MaxRTTms = parseRTT(last["max-rtt"])

	return result
}

// parseRTT parses RouterOS RTT strings like "2ms", "1.5ms", "200us".
func parseRTT(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasSuffix(s, "ms") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		return v
	}
	if strings.HasSuffix(s, "us") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "us"), 64)
		return v / 1000.0
	}
	if strings.HasSuffix(s, "s") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		return v * 1000.0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// SystemIdentity returns the router's name.
func (c *Client) SystemIdentity(ctx context.Context) (string, error) {
	reply, err := c.run(ctx, "/system/identity/print")
	if err != nil {
		return "", err
	}
	if len(reply.Re) == 0 {
		return "", nil
	}
	return reply.Re[0].Map["name"], nil
}

// RouterInfo aggregates basic router metadata.
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

// GetRouterInfo returns combined identity + resource information.
func (c *Client) GetRouterInfo(ctx context.Context) (*RouterInfo, error) {
	identity, err := c.SystemIdentity(ctx)
	if err != nil {
		return nil, err
	}

	reply, err := c.run(ctx, "/system/resource/print",
		"=.proplist=version,platform,board-name,uptime,cpu-load,free-memory,total-memory",
	)
	if err != nil {
		return &RouterInfo{Identity: identity}, nil
	}

	info := &RouterInfo{Identity: identity}
	if len(reply.Re) > 0 {
		m := reply.Re[0].Map
		info.Version = m["version"]
		info.Platform = m["platform"]
		info.BoardName = m["board-name"]
		info.Uptime = m["uptime"]
		info.CPULoad = parseIntField(m["cpu-load"])
		if v, err := strconv.ParseInt(strings.TrimSpace(m["free-memory"]), 10, 64); err == nil {
			info.FreeMemory = v
		}
		if v, err := strconv.ParseInt(strings.TrimSpace(m["total-memory"]), 10, 64); err == nil {
			info.TotalMemory = v
		}
	}
	return info, nil
}

// ListNextHops returns the nexthop resolution table.
func (c *Client) ListNextHops(ctx context.Context) ([]NextHop, error) {
	reply, err := c.run(ctx, "/routing/nexthop/print",
		"=.proplist=.id,gateway,interface,resolved,immediate-gw",
	)
	if err != nil {
		return nil, fmt.Errorf("ListNextHops: %w", err)
	}

	hops := make([]NextHop, 0, len(reply.Re))
	for _, s := range reply.Re {
		h := NextHop{
			ID:        s.Map[".id"],
			Gateway:   s.Map["gateway"],
			Interface: s.Map["interface"],
			Resolved:  parseBool(s.Map["resolved"]),
			Immediate: s.Map["immediate-gw"],
		}
		hops = append(hops, h)
	}
	return hops, nil
}
