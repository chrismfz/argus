package enrich

import (
    "fmt"
    "strconv"
    "strings"
    "sync"
    "time"
    "argus/internal/config"
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


func CollectSNMPStats() ([]SNMPStat, error) {
    cache := IFNames
    snmp := SNMPClient

    if cache == nil || snmp == nil {
        return nil, fmt.Errorf("SNMP not initialized")
    }

    cache.RLock()
    defer cache.RUnlock()

var stats []SNMPStat
    now := time.Now()

    for index, name := range cache.names {
        oids := []string{
            ".1.3.6.1.2.1.2.2.1.10." + strconv.Itoa(int(index)), // ifInOctets
            ".1.3.6.1.2.1.2.2.1.16." + strconv.Itoa(int(index)), // ifOutOctets
            ".1.3.6.1.2.1.2.2.1.11." + strconv.Itoa(int(index)), // ifInUcastPkts
            ".1.3.6.1.2.1.2.2.1.17." + strconv.Itoa(int(index)), // ifOutUcastPkts
            ".1.3.6.1.2.1.2.2.1.7." + strconv.Itoa(int(index)),  // ifAdminStatus
            ".1.3.6.1.2.1.2.2.1.8." + strconv.Itoa(int(index)),  // ifOperStatus
            ".1.3.6.1.2.1.2.2.1.3." + strconv.Itoa(int(index)),  // ifType
        }

        result, err := snmp.Get(oids)
        if err != nil {
            continue
        }

        var rxBytes, txBytes, rxPkts, txPkts, ifType uint64
        var admin, oper uint8

        for _, v := range result.Variables {
            oid := v.Name
            val := gosnmp.ToBigInt(v.Value).Uint64()

            switch {
            case strings.Contains(oid, ".10."): rxBytes = val
            case strings.Contains(oid, ".16."): txBytes = val
            case strings.Contains(oid, ".11."): rxPkts = val
            case strings.Contains(oid, ".17."): txPkts = val
            case strings.Contains(oid, ".7."):  admin = uint8(val)
            case strings.Contains(oid, ".8."):  oper = uint8(val)
            case strings.Contains(oid, ".3."):  ifType = val
            }
        }

stats = append(stats, SNMPStat{
            Timestamp:    now,
            IfIndex:      index,
            IfName:       name,
            RxBytes:      rxBytes,
            TxBytes:      txBytes,
            RxPackets:    rxPkts,
            TxPackets:    txPkts,
            AdminStatus:  admin,
            OperStatus:   oper,
            IfType:       ifType,
            IfTypeString: IfTypeToString(ifType),
        })
    }

    return stats, nil
}


var ifTypeMap = map[uint64]string{
    1:    "other",
    6:    "ethernetCsmacd",
    23:   "ppp",
    24:   "softwareLoopback",
    53:   "propVirtual",
    131:  "tunnel",
    135:  "l2vlan",
    136:  "l3ipvlan",
    161:  "ieee8023adLag",
    209:  "bridge",
    229:  "ieee80211Radio",
    // ... πρόσθεσε όσους χρειάζεσαι
}

func IfTypeToString(code uint64) string {
    if str, ok := ifTypeMap[code]; ok {
        return str
    }
    return "unknown"
}
