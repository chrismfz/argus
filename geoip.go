package main

import (
	"net"
	"fmt"
	"sync"
	"github.com/oschwald/geoip2-golang"
)
type GeoIP struct {
	asnDB  *geoip2.Reader
	cityDB *geoip2.Reader
        asnNameCache sync.Map // IP string → ASN Name
	countryCache sync.Map // IP string → country code (e.g. "US")
	cityCache    sync.Map // IP string → city name
	asnNumCache  sync.Map // IP string → ASN number (uint32)
}

func NewGeoIP(asnPath, cityPath string) (*GeoIP, error) {
	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		return nil, err
	}
	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, err
	}
	return &GeoIP{
		asnDB:  asnDB,
		cityDB: cityDB,
	}, nil
}

func (g *GeoIP) GetASNNumber(ip string) uint32 {
    if val, ok := g.asnNumCache.Load(ip); ok {
        return val.(uint32)
    }

    parsed := net.ParseIP(ip)
    if parsed == nil {
        return 0
    }

    record, err := g.asnDB.ASN(parsed)
    if err != nil {
        return 0
    }

    g.asnNumCache.Store(ip, record.AutonomousSystemNumber)
    return uint32(record.AutonomousSystemNumber)
}

func (g *GeoIP) GetASNName(ip string) string {
    if val, ok := g.asnNameCache.Load(ip); ok {
        return val.(string)
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
    g.asnNameCache.Store(ip, name)
    return name
}

func (g *GeoIP) GetCountry(ip string) string {
    if val, ok := g.countryCache.Load(ip); ok {
        return val.(string)
    }

    parsed := net.ParseIP(ip)
    if parsed == nil {
        return ""
    }

    record, err := g.cityDB.Country(parsed)
    if err != nil || record == nil || record.Country.IsoCode == "" {
        return ""
    }

    g.countryCache.Store(ip, record.Country.IsoCode)
    return record.Country.IsoCode
}

func (g *GeoIP) GetCity(ip string) string {
    if val, ok := g.cityCache.Load(ip); ok {
        return val.(string)
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
    g.cityCache.Store(ip, name)
    return name
}

func (g *GeoIP) ASNName(asn uint32) string {
    return fmt.Sprintf("AS%d", asn)
}
