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
        riskLogger    *log.Logger
        riskOnce      sync.Once
        riskPath      = "risk.log"
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


// --- Risk logger (mean-based “interesting” anomalies) ---

// SetRiskLogPath lets the caller override the risk log path before first use.
func SetRiskLogPath(path string) {
        if path == "" {
                return
        }
        // Only override before initialization
        if riskLogger == nil {
                riskPath = path
        }
}

func initRiskLogger() {
        f, err := os.OpenFile(riskPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                log.Fatalf("open %s: %v", riskPath, err)
        }
        riskLogger = log.New(f, "", log.Ldate|log.Ltime)
}

func logRiskLine(format string, args ...any) {
        riskOnce.Do(initRiskLogger)
        riskLogger.Printf(format, args...)
}
