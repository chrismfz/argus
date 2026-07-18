package rib

// DebugStats returns element counts of the multi-path RIB for the
// /debug/memstats census. With adj-in polling on a full transit feed the
// entries map holds ~1M prefixes, each with an active path plus alt paths —
// alongside the bgp cidranger trie this is the other large fixed consumer.
func (w *Watcher) DebugStats() map[string]any {
	w.mu.RLock()
	defer w.mu.RUnlock()
	altPaths := 0
	for _, e := range w.entries {
		altPaths += len(e.AltPaths)
	}
	return map[string]any{
		"prefixes":  len(w.entries),
		"alt_paths": altPaths,
	}
}
