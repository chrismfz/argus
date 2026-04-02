package routeros

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ListBGPSessions returns all BGP sessions from /rest/routing/bgp/session.
func (c *Client) ListBGPSessions(ctx context.Context) ([]BGPSession, error) {
	var raw []map[string]string
	if err := c.get(ctx, "routing/bgp/session", nil, &raw); err != nil {
		return nil, fmt.Errorf("ListBGPSessions: %w", err)
	}
	sessions := make([]BGPSession, 0, len(raw))
	for _, m := range raw {
		sessions = append(sessions, parseBGPSession(m))
	}
	return sessions, nil
}

// ListBGPPeers returns configured BGP connections from /rest/routing/bgp/connection.
func (c *Client) ListBGPPeers(ctx context.Context) ([]BGPPeer, error) {
	var raw []map[string]string
	if err := c.get(ctx, "routing/bgp/connection", nil, &raw); err != nil {
		return nil, fmt.Errorf("ListBGPPeers: %w", err)
	}
	peers := make([]BGPPeer, 0, len(raw))
	for _, m := range raw {
		p := BGPPeer{
			ID:            m[".id"],
			Name:          m["name"],
			RemoteAddress: m["remote.address"],
			LocalAddress:  m["local.address"],
			Disabled:      parseBool(m["disabled"]),
			Comment:       m["comment"],
			InputFilter:   m["input.filter"],
			OutputFilter:  m["output.filter"],
		}
		if v, err := strconv.ParseUint(m["remote.as"], 10, 32); err == nil {
			p.RemoteAS = uint32(v)
		}
		if v, err := strconv.ParseUint(m["local.as"], 10, 32); err == nil {
			p.LocalAS = uint32(v)
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// ListFilterRules returns routing filter rules from /rest/routing/filter/rule.
func (c *Client) ListFilterRules(ctx context.Context) ([]FilterRule, error) {
	var raw []map[string]string
	if err := c.get(ctx, "routing/filter/rule", nil, &raw); err != nil {
		return nil, fmt.Errorf("ListFilterRules: %w", err)
	}
	rules := make([]FilterRule, 0, len(raw))
	for _, m := range raw {
		rules = append(rules, FilterRule{
			ID:       m[".id"],
			Chain:    m["chain"],
			Rule:     m["rule"],
			Disabled: parseBool(m["disabled"]),
			Comment:  m["comment"],
		})
	}
	return rules, nil
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
	if v, err := strconv.ParseUint(m["remote.as"], 10, 32); err == nil {
		s.RemoteAS = uint32(v)
	}
	if v, err := strconv.ParseUint(m["local.as"], 10, 32); err == nil {
		s.LocalAS = uint32(v)
	}
	s.PrefixesReceived, _ = strconv.Atoi(m["prefix-count"])
	s.PrefixesAdv, _ = strconv.Atoi(m["output.prefix-count"])

	switch {
	case s.Established:
		s.State = StateEstablished
	case m["uptime"] == "" && !s.Established:
		s.State = StateActive
	default:
		s.State = StateIdle
	}
	if s.UptimeRaw != "" {
		s.Uptime = parseROSUptime(s.UptimeRaw)
	}
	return s
}

func parseROSUptime(s string) time.Duration {
	if s == "" {
		return 0
	}
	units := map[string]time.Duration{
		"w": 7 * 24 * time.Hour,
		"d": 24 * time.Hour,
		"h": time.Hour,
		"m": time.Minute,
		"s": time.Second,
	}
	var total time.Duration
	num := ""
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			num += string(ch)
		} else {
			if mul, ok := units[string(ch)]; ok && num != "" {
				n, _ := strconv.Atoi(num)
				total += time.Duration(n) * mul
			}
			num = ""
		}
	}
	return total
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

// MatchingRules returns filter rules mentioning a given ASN.
func MatchingRules(rules []FilterRule, asn uint32) []FilterRule {
	asnStr := fmt.Sprintf("%d", asn)
	var matched []FilterRule
	for _, r := range rules {
		if strings.Contains(r.Rule, asnStr) || strings.Contains(r.Comment, asnStr) {
			matched = append(matched, r)
		}
	}
	return matched
}
