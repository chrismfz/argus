package detection

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
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
func LogDetection(rule DetectionRule, flows []Flow) {
	once.Do(initLogger)

	if len(flows) == 0 {
		fmt.Println("LogDetection called with empty flows for rule: %s", rule.Name) // Debug log
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

	// Log source IPs without enrichment details
	for ip := range srcCount {
		detectionLogger.Printf("         SRC: %-15s", ip)
	}
	detectionLogger.Println("---")
	fmt.Println("Alert logged for rule '%s'", rule.Name) // Debug log
}

