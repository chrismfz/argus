package enrich

import (
    "fmt"
    "strconv"
    "strings"
    "sync"
    "time"
    "flowenricher/config"
    "github.com/gosnmp/gosnmp"
)

type IFNameCache struct {
    sync.RWMutex
    names map[uint32]string
}

type InterfaceStat struct {
    Index   uint32 `json:"index"`
    Name    string `json:"name"`
    RxBytes uint64 `json:"rx_bytes"`
    TxBytes uint64 `json:"tx_bytes"`
}


func NewIFNameCache() *IFNameCache {
    return &IFNameCache{
        names: make(map[uint32]string),
    }
}

func (c *IFNameCache) StartRefreshLoop(snmp *gosnmp.GoSNMP, interval time.Duration) {
    go func() {
        for {
            names := make(map[uint32]string)

            err := snmp.Walk(".1.3.6.1.2.1.31.1.1.1.1", func(pdu gosnmp.SnmpPDU) error {
                parts := strings.Split(pdu.Name, ".")
                indexStr := parts[len(parts)-1]
                index, _ := strconv.Atoi(indexStr)
                name := string(pdu.Value.([]byte))
                names[uint32(index)] = name
                return nil
            })

            if err != nil {
                fmt.Printf("[SNMP] Walk error: %v\n", err)
            } else {
                c.Lock()
                c.names = names
                c.Unlock()
            }

            time.Sleep(interval)
        }
    }()
}

func (c *IFNameCache) Get(index uint32) string {
    c.RLock()
    defer c.RUnlock()
    return c.names[index]
}


func InitSNMPClient(cfg config.SNMPConfig) (*gosnmp.GoSNMP, error) {
    if !cfg.Enabled {
        return nil, nil
    }

    client := &gosnmp.GoSNMP{
        Target:    cfg.Target,
        Community: cfg.Community,
        Port:      cfg.Port,
        Version:   gosnmp.Version2c,
        Timeout:   time.Duration(cfg.Timeout) * time.Second,
        Retries:   cfg.Retries,
    }

    err := client.Connect()
    if err != nil {
        return nil, fmt.Errorf("SNMP connect error: %w", err)
    }

    return client, nil
}



func GetInterfaceTraffic(snmp *gosnmp.GoSNMP, cache *IFNameCache) ([]InterfaceStat, error) {
    cache.RLock()
    defer cache.RUnlock()

    var stats []InterfaceStat

    for index, name := range cache.names {
        rxOid := ".1.3.6.1.2.1.2.2.1.10." + strconv.Itoa(int(index))
        txOid := ".1.3.6.1.2.1.2.2.1.16." + strconv.Itoa(int(index))

        result, err := snmp.Get([]string{rxOid, txOid})
        if err != nil {
            continue // optionally: log.Printf("SNMP get failed for %s: %v", name, err)
        }

        var rxBytes, txBytes uint64
        for _, variable := range result.Variables {
            value := gosnmp.ToBigInt(variable.Value).Uint64()
            if strings.Contains(variable.Name, ".10.") {
                rxBytes = value
            } else if strings.Contains(variable.Name, ".16.") {
                txBytes = value
            }
        }

        stats = append(stats, InterfaceStat{
            Index:   index,
            Name:    name,
            RxBytes: rxBytes,
            TxBytes: txBytes,
        })
    }

    return stats, nil
}

var SNMPClient *gosnmp.GoSNMP
var IFNames *IFNameCache

