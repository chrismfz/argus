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
