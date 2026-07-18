package bgp

// DebugStats returns counts of the BGP-side in-memory state for the
// /debug/memstats census. PathCount tracks paths inserted into the cidranger
// RIB trie — with a full transit feed this is ~1M entries and the dominant
// fixed memory cost of the process (each entry is a BGPEnrichedEntry; with
// store_as_path enabled it also carries the AS-path strings).
func DebugStats() map[string]any {
	announceMu.RLock()
	announced := len(announcedPrefixes)
	announceMu.RUnlock()
	return map[string]any{
		"ranger_paths":       GetPathCount(),
		"announced_prefixes": announced,
	}
}
