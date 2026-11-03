package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"argus/internal/config"
	"argus/internal/mailwatch"
)

// mailWatchBucket is the configured bucket width (sparkline resolution).
func mailWatchBucket() time.Duration {
	if config.AppConfig != nil && config.AppConfig.MailWatch.Bucket > 0 {
		return config.AppConfig.MailWatch.Bucket
	}
	return 5 * time.Minute
}

// handleMailWatchSenders lists our addresses that sent to remote mail ports
// in the last ?hours= (default 24, max 720), busiest first.
//
//	GET /mailwatch/senders?hours=24&limit=200
func handleMailWatchSenders(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB not initialized"})
		return
	}
	q := r.URL.Query()
	hours := atoiDefault(q.Get("hours"), 24)
	if hours <= 0 || hours > 720 {
		hours = 24
	}
	limit := atoiDefault(q.Get("limit"), 200)
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	bucket := mailWatchBucket()
	senders, err := mailwatch.Senders(DB, time.Now().Add(-time.Duration(hours)*time.Hour), bucket, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if Resolver != nil {
		for i := range senders {
			senders[i].PTR = Resolver.LookupPTR(senders[i].IP)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hours":          hours,
		"bucket_seconds": int(bucket.Seconds()),
		"senders":        senders,
	})
}

// handleMailWatchIP returns one sender's memory row, bucket timeline and
// merged top destinations over the last ?hours= (default 168, max 720).
//
//	GET /mailwatch/ip?ip=84.54.49.205&hours=168
func handleMailWatchIP(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB not initialized"})
		return
	}
	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ip"})
		return
	}
	hours := atoiDefault(q.Get("hours"), 168)
	if hours <= 0 || hours > 720 {
		hours = 168
	}
	h, err := mailwatch.History(DB, ip, time.Now().Add(-time.Duration(hours)*time.Hour), 20)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if Resolver != nil {
		h.PTR = Resolver.LookupPTR(ip)
	}
	writeJSON(w, http.StatusOK, h)
}

// handleMailWatchAlerts lists stored baseline alerts, newest first.
//
//	GET /mailwatch/alerts?hours=168&ip=&limit=200
func handleMailWatchAlerts(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB not initialized"})
		return
	}
	q := r.URL.Query()
	hours := atoiDefault(q.Get("hours"), 168)
	if hours <= 0 || hours > 24*90 {
		hours = 168
	}
	limit := atoiDefault(q.Get("limit"), 200)
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	ip := strings.TrimSpace(q.Get("ip"))
	if ip != "" && net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ip"})
		return
	}
	alerts, err := mailwatch.Alerts(DB, time.Now().Add(-time.Duration(hours)*time.Hour), ip, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "alerts": alerts})
}
