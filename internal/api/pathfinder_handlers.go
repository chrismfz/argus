package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
//	"sync"
	"time"

	"argus/internal/pathfinder"
	"argus/internal/routeros"
)

// PathfinderResolver is initialised by main.go after the BGP server is ready.
var PathfinderResolver *pathfinder.Resolver

// PathfinderROSClient is the RouterOS API client (may be nil if ROS disabled).
var PathfinderROSClient *routeros.Client

// GET /pathfinder/prefix?prefix=62.103.0.0/16
func handlePathfinderPrefix(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		jsonErr(w, http.StatusBadRequest, "missing ?prefix=")
		return
	}
	if PathfinderResolver == nil {
		jsonErr(w, http.StatusServiceUnavailable, "pathfinder not ready — BGP not connected")
		return
	}

	// 1. GoBGP best path (communities, full AS-path, attributes)
	result, err := PathfinderResolver.ResolvePrefix(prefix)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 2. RouterOS /routing/route — all paths with full BGP attrs + ping RTT
	if PathfinderROSClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		rosRoutes, err := PathfinderROSClient.ListDetailedRoutesByPrefix(ctx, prefix)
		if err == nil && len(rosRoutes) > 0 {
			summaries := rosRoutesToSummary(rosRoutes)
			// Ping unique next-hops concurrently
			pingResults := pingUniqueGateways(ctx, summaries)
			for i := range summaries {
				if pr, ok := pingResults[summaries[i].Gateway]; ok {
					summaries[i].RTTms = pr.AvgRTTms
					summaries[i].RTTLoss = pr.LossPct
					if pr.Error != "" {
						summaries[i].RTTError = pr.Error
					}
				}
			}
			result.AllPaths = summaries
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// GET /pathfinder/asn?asn=5408&name=GR-NET
func handlePathfinderASN(w http.ResponseWriter, r *http.Request) {
	asnStr := r.URL.Query().Get("asn")
	if asnStr == "" {
		jsonErr(w, http.StatusBadRequest, "missing ?asn=")
		return
	}
	asn64, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid asn: "+asnStr)
		return
	}
	asnName := r.URL.Query().Get("name")

	if PathfinderResolver == nil {
		jsonErr(w, http.StatusServiceUnavailable, "pathfinder not ready — BGP not connected")
		return
	}
	result, err := PathfinderResolver.ResolveASN(uint32(asn64), asnName)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// rosRoutesToSummary converts []routeros.Route → []pathfinder.RouteSummary.
func rosRoutesToSummary(routes []routeros.Route) []pathfinder.RouteSummary {
	out := make([]pathfinder.RouteSummary, 0, len(routes))
	for _, r := range routes {
		s := pathfinder.RouteSummary{
			Gateway:   r.Gateway,
			Interface: r.Interface,
			Distance:  r.Distance,
			Active:    r.Active,
			Upstream:  routeros.UpstreamLabelFromIface(r.Interface),
		}
		if r.BGPAttr != nil {
			s.Contribution = r.BGPAttr.Contribution
			s.SessionName = r.BGPAttr.SessionName
			s.BelongsTo = r.BGPAttr.BelongsTo
			s.ASPath = r.BGPAttr.ASPath
			s.Hops = len(r.BGPAttr.ASPath)
			s.LocalPref = r.BGPAttr.LocalPref
			s.MED = r.BGPAttr.MED
			s.Communities = r.BGPAttr.Communities
			s.LargeCommunities = r.BGPAttr.LargeCommunities
		}
		out = append(out, s)
	}
	return out
}

// pingUniqueGateways pings each unique gateway IP concurrently.
// Returns a map of gateway IP → PingResult.
// Uses 3 pings per host with a shared timeout from the parent context.
func pingUniqueGateways(ctx context.Context, summaries []pathfinder.RouteSummary) map[string]routeros.PingResult {
	if PathfinderROSClient == nil {
		return nil
	}
	seen := make(map[string]struct{})
	results := make(map[string]routeros.PingResult)
	for _, s := range summaries {
		if s.Gateway == "" {
			continue
		}
		if _, ok := seen[s.Gateway]; ok {
			continue
		}
		seen[s.Gateway] = struct{}{}
		// Sequential — connection is not concurrent-safe
		results[s.Gateway] = PathfinderROSClient.PingHost(ctx, s.Gateway, 3)
	}
	return results
}
