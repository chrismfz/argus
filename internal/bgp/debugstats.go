package bgp

// DebugStats returns counts of the BGP-side in-memory state for the
// /debug/memstats census. paths_processed is the running count of best-path
// updates inserted into the cidranger trie (a churn counter, NOT the trie
// size — the api layer adds ranger_size from Ranger.Len()). With a full
// transit feed the trie holds ~1M entries and is the dominant fixed memory
// cost of the process (each entry is a BGPEnrichedEntry; with store_as_path
// enabled it also carries the AS-path strings).
func DebugStats() map[string]any {
	announceMu.RLock()
	announced := len(announcedPrefixes)
	announceMu.RUnlock()
	return map[string]any{
		"paths_processed":    GetPathCount(),
		"announced_prefixes": announced,
	}
}
