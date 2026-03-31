package routeros

import (
	"context"
	"fmt"
)

// ListNextHops returns the nexthop resolution table from /routing/nexthop.
// Useful for understanding recursive next-hop resolution.
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

// SystemIdentity returns the router's name from /system/identity.
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

// RouterInfo aggregates basic router metadata for dashboard display.
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
		// Non-fatal — return what we have
		return &RouterInfo{Identity: identity}, nil
	}

	info := &RouterInfo{Identity: identity}
	if len(reply.Re) > 0 {
		m := reply.Re[0].Map
		info.Version = m["version"]
		info.Platform = m["platform"]
		info.BoardName = m["board-name"]
		info.Uptime = m["uptime"]
		if v, err := parseInt64(m["cpu-load"]); err == nil {
			info.CPULoad = int(v)
		}
		if v, err := parseInt64(m["free-memory"]); err == nil {
			info.FreeMemory = v
		}
		if v, err := parseInt64(m["total-memory"]); err == nil {
			info.TotalMemory = v
		}
	}
	return info, nil
}

func parseInt64(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}
