package main

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type GeoIP struct {
	asnDB  *geoip2.Reader
	cityDB *geoip2.Reader
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
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	record, err := g.asnDB.ASN(parsed)
	if err != nil {
		return 0
	}
	return uint32(record.AutonomousSystemNumber)
}

func (g *GeoIP) GetASNName(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := g.asnDB.ASN(parsed)
	if err != nil {
		return ""
	}
	return record.AutonomousSystemOrganization
}

func (g *GeoIP) GetCountry(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := g.cityDB.Country(parsed)
	if err != nil || record == nil || record.Country.IsoCode == "" {
		return ""
	}
	return record.Country.IsoCode
}

func (g *GeoIP) GetCity(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := g.cityDB.City(parsed)
	if err != nil || record.City.Names == nil {
		return ""
	}
	return record.City.Names["en"]
}
