package detection

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"os"
	"flowenricher/enrich"
)


var (
	debugEngine   = false
	debugLog      *log.Logger
	debugLogOnce  sync.Once
)

func InitDebugDetection(enabled bool) {
	debugEngine = enabled
	if enabled {
		debugLogOnce.Do(func() {
			f, err := os.OpenFile("detection.debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("[WARN] Cannot open detection.debug.log: %v", err)
				return
			}
			debugLog = log.New(f, "", log.Ldate|log.Ltime)
		})
	}
}

func DlogEngine(msg string, args ...interface{}) {
	if debugEngine && debugLog != nil {
		debugLog.Printf("[DEBUG-ENGINE] "+msg, args...)
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
	Geo *enrich.GeoIP
	DNS *enrich.DNSResolver
//	alertCount map[string]map[string]int // rule → srcIP → count // Old way store in RAM memory map
	store DetectionStore
	CH *ClickHouseWriter
}

func (e *Engine) SetClickHouseWriter(w *ClickHouseWriter) {
	e.CH = w
}


// ✅ Δημιουργία του detection engine
// Removed geo, resolver, ifnames parameters
func NewEngine(rules []DetectionRule, asn uint32, prefixes []*net.IPNet, maxWin time.Duration, geo *enrich.GeoIP, dns *enrich.DNSResolver, store DetectionStore ) *Engine {
	DlogEngine("NewEngine created with %d rules, maxWindow: %s", len(rules), maxWin.String())
	return &Engine{
		rules:     rules,
		myASN:     asn,
		myNets:    prefixes,
		flows:     make([]Flow, 0),
		maxWindow: maxWin,
		Geo:       geo,
		DNS:       dns,
		store:     store,
//		alertCount: make(map[string]map[string]int), //old RAM
	}
}

// ✅ Προσθήκη flow στο cache
func (e *Engine) AddFlow(f Flow) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flows = append(e.flows, f)
	DlogEngine("Flow added. Current flow cache size: %d. Added: Src=%s, Dst=%s, DstPort=%d, Proto=%s, Timestamp=%s",
		len(e.flows), f.SrcIP, f.DstIP, f.DstPort, f.Proto, f.Timestamp.Format(time.RFC3339Nano))
}

// ✅ Κύρια detection loop
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	DlogEngine("Detection engine Run loop started.")
	for {
		select {
		case <-ctx.Done():
			DlogEngine("Detection engine Run loop stopped by context cancellation.")
			return
		case <-ticker.C:
			DlogEngine("Ticker fired, running detection.")
			e.runDetection()
		}
	}
}

// ✅ Εφαρμογή detection rules κάθε 1s
func (e *Engine) runDetection() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().UTC()
	DlogEngine("runDetection started. Current raw flow cache size: %d", len(e.flows))

	// Κρατάμε μόνο τα πρόσφατα flows εντός του window
	cutoff := now.Add(-e.maxWindow)
	var recent []Flow
	for _, f := range e.flows {
		if f.Timestamp.After(cutoff) {
			recent = append(recent, f)
		} else {
			DlogEngine("Flow %s -> %s (at %s) is older than cutoff %s, dropping.", f.SrcIP, f.DstIP, f.Timestamp.Format(time.RFC3339), cutoff.Format(time.RFC3339))
		}
	}
	e.flows = recent
	DlogEngine("Flow cache after cleanup (flows within %s window): %d", e.maxWindow.String(), len(e.flows))

	if len(e.flows) == 0 {
		DlogEngine("No recent flows to evaluate. Skipping rule evaluation.")
		return
	}

	for _, rule := range e.rules {
		DlogEngine("Evaluating rule: %s", rule.Name)
		matched, flows := evaluateRule(rule, recent, e.myNets)
		if !matched {
			DlogEngine("Rule '%s' did not match.", rule.Name)
			continue
		}

		DlogEngine("Rule '%s' matched with %d flows. Actions: %s", rule.Name, len(flows), rule.Action)

		// Πάρε srcIP (χρησιμοποιούμε το πρώτο flow ως δείγμα)
		srcIP := flows[0].SrcIP

// OLD fallback logic (in-memory):
//if e.alertCount[rule.Name] == nil {
//e.alertCount[rule.Name] = make(map[string]int)
//}
//e.alertCount[rule.Name][srcIP]++
//count := e.alertCount[rule.Name][srcIP]
count, err := e.store.IncrementCount(rule.Name, srcIP)
if err != nil {
	log.Printf("[ERROR] Failed to increment detection count for %s/%s: %v", rule.Name, srcIP, err)
	continue
}

	// ➕ Ενημέρωση log
		DlogEngine("IP %s triggered rule '%s' %d time(s)", srcIP, rule.Name, count)

		// Εκτέλεση actions
		for _, act := range parseActions(rule.Action) {
			switch act {
			case "alert":
				LogDetection(rule, flows, e.Geo, e.DNS, count) // 🆕 περνάμε count
			case "clickhouse":
    if e.CH != nil {
        // βασιζόμαστε στο ίδιο enrichment που ήδη έχεις διαθέσιμο στο Engine (e.Geo, e.DNS)
        first := flows[0]
        srcIP := first.SrcIP
        dstIP := first.DstIP

        ptr := e.DNS.LookupPTR(srcIP)
        asn := e.Geo.GetASNNumber(srcIP)
        asnName := e.Geo.GetASNName(srcIP)
        country := e.Geo.GetCountry(srcIP)

        // διάβασε τον συνολικό counter από το store (ή reuse το 'count' που έχεις ήδη)
        total := uint64(count)
        // first_seen/last_seen: αν θες πραγματικά first_seen από SQLite, μπορείς να το fetch-άρεις.
        // Για απλότητα εδώ: χρησιμοποιούμε "τώρα" ως last_seen και
        // αν θες αληθινό first_seen, πέρασέ το από SQLite store όταν θες.
        now := time.Now()
        firstSeen := now // ή από SQLite
        lastSeen := now

        if err := e.CH.UpsertDetectionSnapshot(
            srcIP,
            rule,
            first.Proto,
            first.DstPort,
            dstIP,
            total,
            uint32(len(flows)),
            asn,
            asnName,
            country,
            ptr,
            firstSeen,
            lastSeen,
        ); err != nil {
            log.Printf("[ERROR] clickhouse upsert failed for %s/%s: %v", rule.Name, srcIP, err)
        }
    }
				// TODO
			case "slack":
				// TODO
			case "blackhole":
				if rule.BlackholeCount > 0 && count >= rule.BlackholeCount {
				e.HandleBlackhole(rule, flows, count)
				}
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

