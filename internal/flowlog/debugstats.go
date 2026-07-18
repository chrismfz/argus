package flowlog

// DebugStats returns the in-memory queue state of the flow logger for the
// /debug/memstats census. Nil-safe: returns nil when the flow log is disabled.
func DebugStats() map[string]any {
	if Global == nil {
		return nil
	}
	return map[string]any{
		"queue_depth": len(Global.ch),
		"queue_cap":   cap(Global.ch),
		"drops":       Global.drops.Load(),
	}
}
