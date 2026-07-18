package detection

// DebugStats returns element counts of the detection engine's in-memory state
// for the /debug/memstats census: the raw flow cache (window-bounded, spikes
// with ingest rate under attack), the per-source anomaly windows, the ML
// baseline, and the EWMA risk-memory layer.
func (e *Engine) DebugStats() map[string]any {
	e.mu.Lock()
	out := map[string]any{
		"flow_cache":     len(e.flows),
		"flow_cache_cap": cap(e.flows),
		"rules":          len(e.rules),
		"max_window_sec": e.maxWindow.Seconds(),
	}
	anom := e.anomaly
	e.mu.Unlock()

	if anom != nil {
		anom.mu.Lock()
		srcs := len(anom.bySrc)
		srcFlows := 0
		for _, w := range anom.bySrc {
			srcFlows += len(w.flows)
		}
		out["anomaly_sources"] = srcs
		out["anomaly_source_flows"] = srcFlows
		out["anomaly_baseline"] = len(anom.baseline)
		mem := anom.memory
		anom.mu.Unlock()

		if mem != nil {
			n := 0
			mem.st.Range(func(_, _ any) bool { n++; return true })
			out["memory_tracked_ips"] = n
		}
	}
	return out
}
