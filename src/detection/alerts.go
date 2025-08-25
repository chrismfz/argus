package detection

import (
//	"fmt" // fmt is not strictly needed if only using log.Printf and DlogEngine
	"log"
	"os"
	"sync"
	"time"
	"flowenricher/enrich"
	"fmt"
)


var (
	detectionLogger *log.Logger
	blackholeLogger  *log.Logger
	once            sync.Once
)


func initLoggers() {
	// detection.log
	df, err := os.OpenFile("detections.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open detections.log: %v", err)
	}
	detectionLogger = log.New(df, "", log.Ldate|log.Ltime)

	// blackholes.txt
	bf, err := os.OpenFile("blackholes.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open blackholes.txt: %v", err)
	}
	blackholeLogger = log.New(bf, "", log.Ldate|log.Ltime)
}


func openDetectionLog() (*os.File, error) {
	return os.OpenFile("detections.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

// 🔔 Εγγραφή σε log όταν ταιριάζει κάποιο rule (χωρίς enrichment εδώ)
// Enrichment (GeoIP, PTR, IFName) should be handled upstream (e.g., in main)
// before passing flows to the detection engine, or by a separate enrichment service.

func LogDetection(rule DetectionRule, flows []Flow, geo *enrich.GeoIP, dns *enrich.DNSResolver, count int) {
	once.Do(initLoggers)

	if len(flows) == 0 {
		DlogEngine("LogDetection called with empty flows for rule: %s", rule.Name)
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	first := flows[0]
//	detectionLogger.Printf("[%s] ALERT: Rule='%s' | Flows=%d | Proto=%s | DstPort=%d | Example=%s → %s",
//		timestamp, rule.Name, len(flows), first.Proto, first.DstPort, first.SrcIP, first.DstIP)

  // φτιάξε string για τις ports του rule (single/multi)
  ports := rule.DstPorts()
  var rulePorts string
  if len(ports) == 1 {
      rulePorts = fmt.Sprintf("%d", ports[0])
  } else if len(ports) > 1 {
      rulePorts = fmt.Sprintf("%v", ports)
  } else {
      rulePorts = "-" // no restriction
  }

  detectionLogger.Printf("[%s] ALERT: Rule='%s' | Flows=%d | Proto=%s | RulePorts=%s | Example=%s:%d → %s",
      timestamp, rule.Name, len(flows), first.Proto, rulePorts, first.DstIP, first.DstPort, first.SrcIP)

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

func LogBlackhole(entry string) {
    once.Do(initLoggers)
    blackholeLogger.Println(entry)
}
