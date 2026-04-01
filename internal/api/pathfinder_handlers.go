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
      ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
      defer cancel()
      rosRoutes, err := PathfinderROSClient.ListDetailedRoutesByPrefix(ctx, prefix)
      if err == nil && len(rosRoutes) > 0 {
          // Fetch our own IPs to resolve local peering address per path
          addrCtx, addrCancel := context.WithTimeout(r.Context(), 3*time.Second)
          localAddrs, _ := PathfinderROSClient.ListIPAddresses(addrCtx)
          addrCancel()
          result.AllPaths = rosRoutesToSummary(rosRoutes, localAddrs)
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
func rosRoutesToSummary(routes []routeros.Route, addrs []routeros.IPAddress) []pathfinder.RouteSummary {
    out := make([]pathfinder.RouteSummary, 0, len(routes))
    for _, r := range routes {
        s := pathfinder.RouteSummary{
            Gateway:   r.Gateway,
            Interface: r.Interface,
            Distance:  r.Distance,
            Active:    r.Active,
            Upstream:  routeros.UpstreamLabelFromIface(r.Interface),
            LocalIP:   routeros.LocalIPForGateway(r.Gateway, addrs),
        }
        if r.BGPAttr != nil {
            s.Contribution    = r.BGPAttr.Contribution
            s.SessionName     = r.BGPAttr.SessionName
            s.BelongsTo       = r.BGPAttr.BelongsTo
            s.ASPath          = r.BGPAttr.ASPath
            s.Hops            = len(r.BGPAttr.ASPath)
            s.LocalPref       = r.BGPAttr.LocalPref
            s.MED             = r.BGPAttr.MED
            s.Communities     = r.BGPAttr.Communities
            s.LargeCommunities = r.BGPAttr.LargeCommunities
        }
        out = append(out, s)
    }
    return out
}


// GET /pathfinder/ping?gateway=78.108.36.244
func handlePathfinderPing(w http.ResponseWriter, r *http.Request) {
    gw  := r.URL.Query().Get("gateway")
    src := r.URL.Query().Get("src") // optional
    if gw == "" {
        jsonErr(w, http.StatusBadRequest, "missing ?gateway=")
        return
    }
    if PathfinderROSClient == nil {
        jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
        return
    }
    ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
    defer cancel()
    result := PathfinderROSClient.PingHost(ctx, gw, 3, src)
    jsonOK(w, result)
}

// GET /pathfinder/traceroute?address=212.251.91.1&src=78.108.36.244
func handlePathfinderTraceroute(w http.ResponseWriter, r *http.Request) {
    address := r.URL.Query().Get("address")
    src     := r.URL.Query().Get("src") // our local peering IP e.g. 78.108.36.245
    if address == "" {
        jsonErr(w, http.StatusBadRequest, "missing ?address=")
        return
    }
    if PathfinderROSClient == nil {
        jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
        return
    }
    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
    defer cancel()
    hops, err := PathfinderROSClient.Traceroute(ctx, address, src)
    if err != nil {
        jsonErr(w, http.StatusInternalServerError, err.Error())
        return
    }
    // Check if all hops are empty — means path unreachable via this interface
    hasData := false
    for _, h := range hops {
        if h.Address != "" {
            hasData = true
            break
        }
    }
    if !hasData {
        jsonOK(w, map[string]interface{}{
            "address": address,
            "src":     src,
            "hops":    []interface{}{},
            "error":   "path unreachable via this upstream",
        })
        return
    }
    jsonOK(w, map[string]interface{}{
        "address": address,
        "src":     src,
        "hops":    hops,
    })
}
