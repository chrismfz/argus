package flowstore

// DebugStats returns element counts of the in-memory accumulators for the
// /debug/memstats census. Sub-map totals are summed so a runaway detail
// bucket shows up as a large ip/prefix/port count rather than hiding behind
// the (small) number of (asn, dir) buckets.
func DebugStats() map[string]any {
	if Global == nil {
		return nil
	}
	s := Global
	s.mu.Lock()
	defer s.mu.Unlock()

	var detailIPs, detailPfx, detailPorts, detailCountries, detailProtos int
	for _, d := range s.details {
		detailIPs += len(d.ips)
		detailPfx += len(d.pfx)
		detailPorts += len(d.ports)
		detailCountries += len(d.country)
		detailProtos += len(d.proto)
	}
	return map[string]any{
		"timeline_buckets":  len(s.tl),
		"detail_buckets":    len(s.details),
		"detail_ips":        detailIPs,
		"detail_prefixes":   detailPfx,
		"detail_ports":      detailPorts,
		"detail_countries":  detailCountries,
		"detail_protos":     detailProtos,
		"asn_meta":          len(s.meta), // permanent — one entry per ASN ever seen
		"cap_tracked_ips":   s.limits.MaxTrackedIPs,
		"cap_tracked_pfx":   s.limits.MaxTrackedPrefixes,
		"cap_tracked_ports": s.limits.MaxTrackedPorts,
	}
}
