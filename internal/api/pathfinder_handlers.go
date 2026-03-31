package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"argus/internal/pathfinder"
	"argus/internal/routeros"
)

// PathfinderResolver is initialised by main.go after the BGP server is ready.
var PathfinderResolver *pathfinder.Resolver

// PathfinderROSClient is the RouterOS API client, may be nil if ROS is disabled.
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

	// 1. GoBGP best path (communities, AS-path, full attributes)
	result, err := PathfinderResolver.ResolvePrefix(prefix)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 2. RouterOS all-paths — distance 20 via Synapsecom AND distance 30 via GR-IX,
	// not just the winner that eBGP shows.
	if PathfinderROSClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		rosRoutes, err := PathfinderROSClient.ListRoutesByPrefix(ctx, prefix)
		if err == nil {
			result.AllPaths = rosRoutesToSummary(rosRoutes)
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
	asnName := r.URL.Query().Get("name") // optional, passed from UI

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

// rosRoutesToSummary converts []routeros.Route → []pathfinder.RouteSummary,
// keeping only the fields Pathfinder cares about and avoiding a circular import.
func rosRoutesToSummary(routes []routeros.Route) []pathfinder.RouteSummary {
	out := make([]pathfinder.RouteSummary, 0, len(routes))
	for _, r := range routes {
		s := pathfinder.RouteSummary{
			Gateway:   r.Gateway,
			Interface: r.Interface,
			Distance:  r.Distance,
			Active:    r.Active,
		}
		// Derive upstream label from interface name (sfp1-Synapsecom → Synapsecom)
		s.Upstream = routeros.UpstreamLabelFromIface(r.Interface)
		out = append(out, s)
	}
	return out
}
