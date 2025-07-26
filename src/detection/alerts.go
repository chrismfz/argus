package detection

import (
//	"fmt" // fmt is not strictly needed if only using log.Printf and DlogEngine
	"log"
	"os"
	"sync"
	"time"
	"flowenricher/enrich"
)

// NOTE: IFNameCache, GeoRecord, GeoIP, and DNSResolver interfaces
// are removed from here. They should be defined in 'main' or a separate
// 'enrich' package if needed for enrichment outside of 'detection'.

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

// 🔔 Εγγραφή σε log όταν ταιριάζει κάποιο rule (χωρίς enrichment εδώ)
// Enrichment (GeoIP, PTR, IFName) should be handled upstream (e.g., in main)
// before passing flows to the detection engine, or by a separate enrichment service.

func LogDetection(rule DetectionRule, flows []Flow, geo *enrich.GeoIP, dns *enrich.DNSResolver, count int) {
	once.Do(initLogger)

	if len(flows) == 0 {
		DlogEngine("LogDetection called with empty flows for rule: %s", rule.Name)
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	first := flows[0]
	detectionLogger.Printf("[%s] ALERT: Rule='%s' | Flows=%d | Proto=%s | DstPort=%d | Example=%s → %s",
		timestamp, rule.Name, len(flows), first.Proto, first.DstPort, first.SrcIP, first.DstIP)

	detectionLogger.Printf("         Reason: %s", buildReason(rule))

	// Group by unique SrcIP
	srcCount := make(map[string]int)
	for _, f := range flows {
		srcCount[f.SrcIP]++
	}

	for ip := range srcCount {
		ptr := dns.LookupPTR(ip)
		asn := geo.GetASNNumber(ip)
		asnName := geo.GetASNName(ip)
		country := geo.GetCountry(ip)

		if ptr == "" {
			ptr = "-"
		}
		if asnName == "" {
			asnName = "Unknown"
		}
		if country == "" {
			country = "--"
		}

		detectionLogger.Printf("         SRC: %-15s | PTR: %-30s | ASN: AS%d (%s) | Country: %s | Count: %d",
			ip, ptr, asn, asnName, country, count)
	}

	detectionLogger.Println("---")
	DlogEngine("Alert logged for rule '%s'", rule.Name)
}
