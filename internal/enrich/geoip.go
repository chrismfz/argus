package enrich

import (
	"fmt"
	"net"
	//    "argus/internal/detection"
	"github.com/oschwald/geoip2-golang"
)

// DefaultGeoIPCacheMax is the per-generation cap of each per-IP lookup cache
// (config knob geoip.cache_max_entries; 0 = this default, negative =
// unlimited, matching the repo-wide retention/cap convention). Worst-case
// footprint is ~2×max entries per cache across the four caches.
const DefaultGeoIPCacheMax = 250_000

type GeoIP struct {
	asnDB        *geoip2.Reader
	cityDB       *geoip2.Reader
	asnNameCache *boundedCache // IP string → ASN Name
	countryCache *boundedCache // IP string → country code (e.g. "US")
	cityCache    *boundedCache // IP string → city name
	asnNumCache  *boundedCache // IP string → ASN number (uint32)
}

func NewGeoIP(asnPath, cityPath string, cacheMax int) (*GeoIP, error) {
	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		return nil, err
	}
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, err
	}
	if cacheMax == 0 {
		cacheMax = DefaultGeoIPCacheMax
	} else if cacheMax < 0 {
		cacheMax = 0 // unlimited inside boundedCache
	}
	return &GeoIP{
		asnDB:        asnDB,
		cityDB:       cityDB,
		asnNameCache: newBoundedCache(cacheMax),
		countryCache: newBoundedCache(cacheMax),
		cityCache:    newBoundedCache(cacheMax),
		asnNumCache:  newBoundedCache(cacheMax),
	}, nil
}

func (g *GeoIP) GetASNNumber(ip string) uint32 {
	if val, ok := g.asnNumCache.Get(ip); ok {
		switch v := val.(type) {
		case uint32:
			return v
		case uint:
			return uint32(v)
		case int:
			return uint32(v)
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}

	record, err := g.asnDB.ASN(parsed)
	if err != nil {
		return 0
	}

	asn := uint32(record.AutonomousSystemNumber)
	g.asnNumCache.Put(ip, asn)
	return asn
}

func (g *GeoIP) GetASNName(ip string) string {
	if val, ok := g.asnNameCache.Get(ip); ok {
		if name, ok := val.(string); ok {
			return name
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	record, err := g.asnDB.ASN(parsed)
	if err != nil {
		return ""
	}

	name := record.AutonomousSystemOrganization
	g.asnNameCache.Put(ip, name)
	return name
}

func (g *GeoIP) GetCountry(ip string) string {
	if val, ok := g.countryCache.Get(ip); ok {
		if cc, ok := val.(string); ok {
			return cc
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	record, err := g.cityDB.Country(parsed)
	if err != nil || record == nil || record.Country.IsoCode == "" {
		return ""
	}

	g.countryCache.Put(ip, record.Country.IsoCode)
	return record.Country.IsoCode
}

func (g *GeoIP) GetCity(ip string) string {
	if val, ok := g.cityCache.Get(ip); ok {
		if city, ok := val.(string); ok {
			return city
		}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	record, err := g.cityDB.City(parsed)
	if err != nil || record.City.Names == nil {
		return ""
	}

	name := record.City.Names["en"]
	g.cityCache.Put(ip, name)
	return name
}

func (g *GeoIP) ASNName(asn uint32) string {
	return fmt.Sprintf("AS%d", asn)
}
