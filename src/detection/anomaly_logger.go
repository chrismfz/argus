package detection

import (
	"log"
	"os"
	"sync"
	"time"
)

var (
	anomalyLogger *log.Logger
	anomalyOnce   sync.Once
)

func initAnomalyLogger() {
	f, err := os.OpenFile("anomalies.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("open anomalies.log: %v", err)
	}
	anomalyLogger = log.New(f, "", log.Ldate|log.Ltime)
}

func logAnomalyLine(format string, args ...any) {
	anomalyOnce.Do(initAnomalyLogger)
	anomalyLogger.Printf(format, args...)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
