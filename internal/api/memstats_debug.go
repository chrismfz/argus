package api

// GET /debug/memstats — one-shot memory census of the running daemon.
//
// Returns Go runtime memory stats, the process RSS from /proc/self/status,
// and per-component element counts of every long-lived in-memory structure
// (BGP RIB, rib watcher, telemetry rings, flowstore accumulators, enrichment
// caches, detection engine, flow log queue). This is what `argus debug`
// fetches to answer "where did the 12 GB go" without external tooling.
//
// IP-only (WithMainIPOnly): loopback always allowed, otherwise api.allow_ips.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"argus/internal/alerter"
	"argus/internal/bgp"
	"argus/internal/enrich"
	"argus/internal/flowlog"
	"argus/internal/flowstore"
	"argus/internal/telemetry"
)

var processStart = time.Now()

// Extra census providers wired by main.go for instance-held components that
// have no package singleton (detection engine, rib watcher). Registered once
// at startup, before api.Start().
var (
	debugCompMu     sync.Mutex
	debugComponents = map[string]func() map[string]any{}
)

// RegisterDebugComponent adds a named census provider to /debug/memstats.
// Call from main.go during startup wiring.
func RegisterDebugComponent(name string, fn func() map[string]any) {
	debugCompMu.Lock()
	defer debugCompMu.Unlock()
	debugComponents[name] = fn
}

// procSelfMemory parses VmRSS/VmSize/VmSwap (kB) out of /proc/self/status.
// Returns nil off Linux or on read failure — the census degrades gracefully.
func procSelfMemory() map[string]any {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]any{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		for _, key := range []string{"VmRSS", "VmSize", "VmSwap", "Threads"} {
			if strings.HasPrefix(line, key+":") {
				v := strings.TrimSpace(strings.TrimPrefix(line, key+":"))
				v = strings.TrimSpace(strings.TrimSuffix(v, "kB"))
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					if key == "Threads" {
						out["threads"] = n
					} else {
						out[strings.ToLower(key)+"_kb"] = n
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func handleMemStatsDebug(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	bgpStats := bgp.DebugStats()
	if Ranger != nil {
		// The actual trie size — paths_processed is only a churn counter.
		bgpStats["ranger_size"] = Ranger.Len()
	}
	components := map[string]any{
		"telemetry": telemetry.DebugStats(),
		"flowstore": flowstore.DebugStats(),
		"enrich":    enrich.DebugStats(),
		"bgp":       bgpStats,
	}
	if fl := flowlog.DebugStats(); fl != nil {
		components["flowlog"] = fl
	}
	if alerter.Global != nil {
		components["alerter"] = map[string]any{
			"contacts":        len(alerter.Global.Snapshot()),
			"broadcast_queue": len(alerter.Broadcast),
		}
	}
	debugCompMu.Lock()
	for name, fn := range debugComponents {
		if fn != nil {
			components[name] = fn()
		}
	}
	debugCompMu.Unlock()

	res := map[string]any{
		"ts":         time.Now().Unix(),
		"uptime_sec": int64(time.Since(processStart).Seconds()),
		"goroutines": runtime.NumGoroutine(),
		"go_mem": map[string]any{
			"heap_alloc":      ms.HeapAlloc,
			"heap_inuse":      ms.HeapInuse,
			"heap_idle":       ms.HeapIdle,
			"heap_released":   ms.HeapReleased,
			"heap_sys":        ms.HeapSys,
			"heap_objects":    ms.HeapObjects,
			"stack_inuse":     ms.StackInuse,
			"sys":             ms.Sys,
			"num_gc":          ms.NumGC,
			"last_gc_unix":    int64(ms.LastGC / 1e9),
			"gc_cpu_fraction": ms.GCCPUFraction,
		},
		"process":    procSelfMemory(),
		"components": components,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
