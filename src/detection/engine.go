package detection

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Flow struct remains the same, as it's a core data structure for detection
type Flow struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Proto     string
	Bytes     uint64
	Packets   uint64
	TCPFlags  uint8
}

type Engine struct {
	mu        sync.Mutex
	flows     []Flow
	rules     []DetectionRule
	myASN     uint32
	myNets    []*net.IPNet
	// Removed resolver, geoip, ifnames fields from Engine
	maxWindow time.Duration
}

// ✅ Δημιουργία του detection engine
// Removed geo, resolver, ifnames parameters
func NewEngine(rules []DetectionRule, asn uint32, prefixes []*net.IPNet, maxWin time.Duration) *Engine {
	return &Engine{
		rules:     rules,
		// Removed geoip, resolver, ifnames assignments
		myASN:     asn,
		myNets:    prefixes,
		flows:     make([]Flow, 0),
		maxWindow: maxWin,
	}
}

// ✅ Προσθήκη flow στο cache
func (e *Engine) AddFlow(f Flow) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flows = append(e.flows, f)
}

// ✅ Κύρια detection loop
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runDetection()
		}
	}
}

// ✅ Εφαρμογή detection rules κάθε 1s
func (e *Engine) runDetection() {
	e.mu.Lock()
	now := time.Now()

	// Διατήρηση flows μέσα στο maxWindow
	cutoff := now.Add(-e.maxWindow)
	var recent []Flow
	for _, f := range e.flows {
		if f.Timestamp.After(cutoff) {
			recent = append(recent, f)
		}
	}
	e.flows = recent
	e.mu.Unlock()

	// Εφαρμογή detection rules
	for _, rule := range e.rules {
		matched, flows := evaluateRule(rule, recent, e.myNets)
		if !matched {
			continue
		}

		for _, act := range parseActions(rule.Action) {
			switch act {
			case "alert":
				// Updated LogDetection call to match new signature
				LogDetection(rule, flows)
			case "clickhouse":
				// TODO: Write to ClickHouse detection table
			case "slack":
				// TODO: Post to Slack webhook
			case "blackhole":
				// TODO: Send to BGP or firewall API
			default:
				log.Printf("[WARN] Unknown action: %s for rule %s", act, rule.Name)
			}
		}
	}
}

// ✅ Helper: διαχωρισμός action list (π.χ. "alert, clickhouse")
func parseActions(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ✅ Helper για πρωτόκολλα
func ProtocolToString(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "unknown"
	}
}

