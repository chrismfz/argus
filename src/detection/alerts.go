package detection

import (
    "fmt"
    "log"
    "sync"
    "time"
    "os"
    "github.com/gosnmp/gosnmp"
)

type IFNameCache interface {
    StartRefreshLoop(snmp *gosnmp.GoSNMP, interval time.Duration)
    Get(index uint32) string
}


// ✅ Τύπος GeoRecord κοινός για Lookup
type GeoRecord struct {
    ASN     uint32
    ASNName string
    Country string
}

type GeoIP interface {
    Lookup(ip string) (GeoRecord, bool)
}

type DNSResolver interface {
    Lookup(ip string) (string, bool)
}

var (
    detectionLogger *log.Logger
    once            sync.Once
)

func initLogger() {
    f, err := openDetectionLog()
    if err != nil {
        log.Fatalf("Failed to open detections.log: %v", err)
    }
    detectionLogger = log.New(f, "", log.Ldate|log.Ltime)
}

func openDetectionLog() (*os.File, error) {
    return os.OpenFile("detections.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

// 🔔 Εγγραφή σε log όταν ταιριάζει κάποιο rule (με enrichment)
func LogDetection(rule DetectionRule, flows []Flow, geo GeoIP, resolver DNSResolver) {
    once.Do(initLogger)

    if len(flows) == 0 {
        return
    }

    timestamp := time.Now().Format(time.RFC3339)
    first := flows[0]
    detectionLogger.Printf("[%s] ALERT: Rule='%s' | Flows=%d | Proto=%s | DstPort=%d | Example=%s → %s",
        timestamp, rule.Name, len(flows), first.Proto, first.DstPort, first.SrcIP, first.DstIP)

    detectionLogger.Printf("         Reason: %s", buildReason(rule))

    srcCount := make(map[string]int)
    for _, f := range flows {
        srcCount[f.SrcIP]++
    }

    for ip := range srcCount {
        geoCountry := "?"
        asn := "?"
        asnName := "?"
        ptr := "?"

        if record, ok := geo.Lookup(ip); ok {
            geoCountry = record.Country
            asn = fmt.Sprintf("%d", record.ASN)
            asnName = record.ASNName
        }

        if hostname, ok := resolver.Lookup(ip); ok {
            ptr = hostname
        }

        detectionLogger.Printf("         SRC: %-15s | PTR: %-30s | ASN: %-8s | ASNAME: %-30s | COUNTRY: %s",
            ip, ptr, asn, asnName, geoCountry)
    }
    detectionLogger.Println("---")
}
