package routeros

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ListBGPSessions returns all BGP sessions from /routing/bgp/session.
// This is what replaces your bgp-feeder RouterOS script — Argus polls
// this directly instead of the router pushing via HTTP.
func (c *Client) ListBGPSessions(ctx context.Context) ([]BGPSession, error) {
	reply, err := c.run(ctx, "/routing/bgp/session/print",
		"=.proplist=.id,name,remote.address,remote.as,local.address,local.as,"+
			"established,uptime,prefix-count,output.prefix-count,disabled,dynamic,connection",
	)
	if err != nil {
		return nil, fmt.Errorf("ListBGPSessions: %w", err)
	}

	sessions := make([]BGPSession, 0, len(reply.Re))
	for _, s := range reply.Re {
		sess := parseBGPSession(s.Map)
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// GetBGPSession returns a single session by name.
func (c *Client) GetBGPSession(ctx context.Context, name string) (*BGPSession, error) {
	sessions, err := c.ListBGPSessions(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if s.Name == name {
			cp := s
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("BGP session %q not found", name)
}

// ── Parsing ───────────────────────────────────────────────────────────────────

func parseBGPSession(m map[string]string) BGPSession {
	s := BGPSession{
		ID:             m[".id"],
		Name:           m["name"],
		RemoteAddress:  m["remote.address"],
		LocalAddress:   m["local.address"],
		ConnectionName: m["connection"],
		Established:    parseBool(m["established"]),
		Disabled:       parseBool(m["disabled"]),
		Dynamic:        parseBool(m["dynamic"]),
		UptimeRaw:      m["uptime"],
	}

	if ra64, err := strconv.ParseUint(m["remote.as"], 10, 32); err == nil {
		s.RemoteAS = uint32(ra64)
	}
	if la64, err := strconv.ParseUint(m["local.as"], 10, 32); err == nil {
		s.LocalAS = uint32(la64)
	}
	s.PrefixesReceived, _ = strconv.Atoi(m["prefix-count"])
	s.PrefixesAdv, _ = strconv.Atoi(m["output.prefix-count"])

	// Derive State from established flag + uptime presence
	switch {
	case s.Established:
		s.State = StateEstablished
	case m["uptime"] == "" && !s.Established:
		s.State = StateActive // trying to connect
	default:
		s.State = StateIdle
	}

	// Parse RouterOS uptime string "3d2h14m5s" → time.Duration
	if s.UptimeRaw != "" {
		s.Uptime = parseROSUptime(s.UptimeRaw)
	}

	return s
}

// parseROSUptime parses RouterOS uptime strings like "2d3h14m5s", "1w2d", "45m30s".
func parseROSUptime(s string) time.Duration {
	if s == "" {
		return 0
	}
	var total time.Duration
	// RouterOS formats: Nw Nd Nh Nm Ns
	units := map[string]time.Duration{
		"w": 7 * 24 * time.Hour,
		"d": 24 * time.Hour,
		"h": time.Hour,
		"m": time.Minute,
		"s": time.Second,
	}
	num := ""
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			num += string(ch)
		} else {
			unit := string(ch)
			if mul, ok := units[unit]; ok && num != "" {
				n, _ := strconv.Atoi(num)
				total += time.Duration(n) * mul
			}
			num = ""
		}
	}
	return total
}

// SessionSummary is a compact representation useful for dashboard cards / alerts.
type SessionSummary struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	Down        int `json:"down"`
}

// Summarise returns aggregate counts from a session list.
func Summarise(sessions []BGPSession) SessionSummary {
	s := SessionSummary{Total: len(sessions)}
	for _, sess := range sessions {
		if sess.Established {
			s.Established++
		} else if !sess.Disabled {
			s.Down++
		}
	}
	return s
}

// UptimeString formats a duration as a compact human string.
func UptimeString(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, mins)
	}
	return fmt.Sprintf("%dm%ds", mins, int(d.Seconds())%60)
}

// ── BGP Peers config (separate from sessions) ─────────────────────────────────

// BGPPeer is a configured BGP peer from /routing/bgp/connection.
// Sessions are ephemeral; peers are config. Together they give the full picture.
type BGPPeer struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RemoteAddress string `json:"remote_address"`
	RemoteAS     uint32 `json:"remote_as"`
	LocalAddress string `json:"local_address"`
	LocalAS      uint32 `json:"local_as"`
	Disabled     bool   `json:"disabled"`
	Comment      string `json:"comment"`
}

// ListBGPPeers returns configured BGP connections from /routing/bgp/connection.
func (c *Client) ListBGPPeers(ctx context.Context) ([]BGPPeer, error) {
	reply, err := c.run(ctx, "/routing/bgp/connection/print",
		"=.proplist=.id,name,remote.address,remote.as,local.address,local.role,disabled,comment",
	)
	if err != nil {
		return nil, fmt.Errorf("ListBGPPeers: %w", err)
	}

	peers := make([]BGPPeer, 0, len(reply.Re))
	for _, s := range reply.Re {
		p := BGPPeer{
			ID:            s.Map[".id"],
			Name:          s.Map["name"],
			RemoteAddress: s.Map["remote.address"],
			LocalAddress:  s.Map["local.address"],
			Disabled:      parseBool(s.Map["disabled"]),
			Comment:       s.Map["comment"],
		}
		if ra, err := strconv.ParseUint(s.Map["remote.as"], 10, 32); err == nil {
			p.RemoteAS = uint32(ra)
		}
		if la, err := strconv.ParseUint(s.Map["local.as"], 10, 32); err == nil {
			p.LocalAS = uint32(la)
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// StateColor returns a CSS variable name for a session state (for dashboard use).
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

// String implements Stringer for BGPSessionState.
func (s BGPSessionState) String() string {
	return strings.ToUpper(string(s))
}
