package enrich

import "sync"

// countSyncMap walks a sync.Map and returns its element count. O(n) — only
// called from the on-demand /debug/memstats census, never on the hot path.
func countSyncMap(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// DebugStats returns element counts of the enrichment caches for the
// /debug/memstats census. The GeoIP caches are keyed per distinct IP seen —
// bounded at ~2× geoip.cache_max_entries per cache (two-generation eviction);
// the PTR cache is TTL-bounded only.
func DebugStats() map[string]any {
	out := map[string]any{}

	if Global != nil && Global.Geo != nil {
		g := Global.Geo
		out["geoip_asn_name_cache"] = g.asnNameCache.Len()
		out["geoip_asn_num_cache"] = g.asnNumCache.Len()
		out["geoip_country_cache"] = g.countryCache.Len()
		out["geoip_city_cache"] = g.cityCache.Len()
	}
	if Global != nil && Global.DNS != nil {
		out["ptr_cache"] = countSyncMap(&Global.DNS.cache)
	}
	if IFNames != nil {
		IFNames.RLock()
		out["snmp_iface_names"] = len(IFNames.names)
		IFNames.RUnlock()
	}
	return out
}
