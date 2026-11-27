package api

import (
	"net"
	"net/http"
	"strings"

	"argus/internal/detection"
	"argus/internal/protectfeed"
)

// ProtectionFeeds is the protection feed manager (nil when disabled).
var ProtectionFeeds *protectfeed.Manager

// handleProtectionFeeds reports each feed's state; with ?ip= it also says
// which feed, if any, covers that address.
//
//	GET /detection/protection-feeds[?ip=104.16.1.1]
func handleProtectionFeeds(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"enabled": ProtectionFeeds != nil, "feeds": []protectfeed.Status{}}
	if ProtectionFeeds != nil {
		out["feeds"] = ProtectionFeeds.Statuses()
	}
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ip"})
			return
		}
		out["ip"] = ip
		out["covered_by"] = detection.ProtectingFeed(ip)
	}
	writeJSON(w, http.StatusOK, out)
}
