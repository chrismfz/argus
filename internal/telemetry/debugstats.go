package telemetry

// DebugStats returns element counts of every long-lived in-memory structure
// owned by this package, for the /debug/memstats census. Cheap: O(ring slots +
// map sizes) under RLock, no allocation of the underlying data.
func DebugStats() map[string]any {
	out := map[string]any{}

	if Global != nil {
		a := Global
		a.mu.RLock()
		asnRingEntries, ifaceRingEntries := 0, 0
		for i := 0; i < RingSize; i++ {
			asnRingEntries += len(a.asnRing[i])
			ifaceRingEntries += len(a.ifaceRing[i])
		}
		out["ring_slots"] = RingSize
		out["asn_ring_entries"] = asnRingEntries
		out["iface_ring_entries"] = ifaceRingEntries
		out["asn_iface_pairs"] = len(a.asnIface)
		out["iface_names"] = len(a.ifaceNames)
		out["pairs_in"] = len(a.pairsIn)
		out["pairs_out"] = len(a.pairsOut)
		out["hosts_in"] = len(a.hostsIn)
		out["hosts_out"] = len(a.hostsOut)
		out["ports"] = len(a.ports)
		a.mu.RUnlock()
	}

	Tap.mu.Lock()
	out["tap_ring"] = Tap.ringLen
	out["tap_clients"] = len(Tap.clients)
	Tap.mu.Unlock()

	RawTap.mu.Lock()
	out["rawtap_ring"] = RawTap.ringLen
	out["rawtap_clients"] = len(RawTap.clients)
	RawTap.mu.Unlock()

	return out
}
