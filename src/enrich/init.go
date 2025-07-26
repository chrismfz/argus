package enrich

import (
    "flowenricher/config"
)

type Enrichers struct {
    Geo     *GeoIP
    DNS     *DNSResolver
    IFNames *IFNameCache
}

func Init(cfg *config.Config) (*Enrichers, error) {
    var e Enrichers
    var err error

    if e.Geo, err = NewGeoIP(cfg.GeoIP.ASNDB, cfg.GeoIP.CityDB); err != nil {
        return nil, err
    }

    e.DNS = NewDNSResolver(cfg.DNS.Nameserver)

    return &e, nil
}
