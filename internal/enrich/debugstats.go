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
// /debug/memstats census. The GeoIP caches are keyed per distinct IP seen and
// have no TTL or cap, so these counts are prime suspects when RSS grows over
// weeks of uptime.
func DebugStats() map[string]any {
	out := map[string]any{}

	if Global != nil && Global.Geo != nil {
		g := Global.Geo
		out["geoip_asn_name_cache"] = countSyncMap(&g.asnNameCache)
		out["geoip_asn_num_cache"] = countSyncMap(&g.asnNumCache)
		out["geoip_country_cache"] = countSyncMap(&g.countryCache)
		out["geoip_city_cache"] = countSyncMap(&g.cityCache)
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
