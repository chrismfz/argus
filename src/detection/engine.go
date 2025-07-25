package detection

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Add a debug flag or function if you want to control these logs
var debugEngine = true // Set to false for production

func dlogEngine(msg string, args ...interface{}) {
	if debugEngine {
		log.Printf("[DEBUG-ENGINE] "+msg, args...)
	}
}

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
	maxWindow time.Duration
}

// ✅ Δημιουργία του detection engine
// Removed geo, resolver, ifnames parameters
func NewEngine(rules []DetectionRule, asn uint32, prefixes []*net.IPNet, maxWin time.Duration) *Engine {
	dlogEngine("NewEngine created with %d rules, maxWindow: %s", len(rules), maxWin.String())
	return &Engine{
		rules:     rules,
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
	dlogEngine("Flow added. Current flow cache size: %d. Added: Src=%s, Dst=%s, DstPort=%d, Proto=%s, Timestamp=%s",
		len(e.flows), f.SrcIP, f.DstIP, f.DstPort, f.Proto, f.Timestamp.Format(time.RFC3339Nano))
}

// ✅ Κύρια detection loop
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	dlogEngine("Detection engine Run loop started.")
	for {
		select {
		case <-ctx.Done():
			dlogEngine("Detection engine Run loop stopped by context cancellation.")
			return
		case <-ticker.C:
			dlogEngine("Ticker fired, running detection.")
			e.runDetection()
		}
	}
}

// ✅ Εφαρμογή detection rules κάθε 1s
func (e *Engine) runDetection() {
	e.mu.Lock()
	defer e.mu.Unlock() // Ensure mutex is unlocked even if there's an early return or panic

	now := time.Now()
	dlogEngine("runDetection started. Current raw flow cache size: %d", len(e.flows))

	// Διατήρηση flows μέσα στο maxWindow
	cutoff := now.Add(-e.maxWindow)
	var recent []Flow
	for _, f := range e.flows {
		if f.Timestamp.After(cutoff) {
			recent = append(recent, f)
		} else {
			dlogEngine("Flow %s -> %s (at %s) is older than cutoff %s, dropping.", f.SrcIP, f.DstIP, f.Timestamp.Format(time.RFC3339), cutoff.Format(time.RFC3339))
		}
	}
	e.flows = recent
	dlogEngine("Flow cache after cleanup (flows within %s window): %d", e.maxWindow.String(), len(e.flows))

	if len(e.flows) == 0 {
		dlogEngine("No recent flows to evaluate. Skipping rule evaluation.")
		return
	}

	// Εφαρμογή detection rules
	for _, rule := range e.rules {
		dlogEngine("Evaluating rule: %s", rule.Name)
		matched, flows := evaluateRule(rule, recent, e.myNets)
		if !matched {
			dlogEngine("Rule '%s' did not match.", rule.Name)
			continue
		}

		dlogEngine("Rule '%s' matched with %d flows. Actions: %s", rule.Name, len(flows), rule.Action)
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

