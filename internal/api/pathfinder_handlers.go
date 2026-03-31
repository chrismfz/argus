package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"argus/internal/pathfinder"

)

// PathfinderResolver is initialised by main.go after the BGP server is ready.
var PathfinderResolver *pathfinder.Resolver
var PathfinderROSClient *routeros.Client


// GET /pathfinder/prefix?prefix=62.103.0.0/16
  func handlePathfinderPrefix(w http.ResponseWriter, r *http.Request) {
      prefix := r.URL.Query().Get("prefix")
      if prefix == "" {
          jsonErr(w, http.StatusBadRequest, "missing ?prefix=")
          return
      }
      if PathfinderResolver == nil {
          jsonErr(w, http.StatusServiceUnavailable, "pathfinder not ready")
          return
      }
 
      // 1. GoBGP best path (communities, AS-path, attributes)
      result, err := PathfinderResolver.ResolvePrefix(prefix)
      if err != nil {
          jsonErr(w, http.StatusInternalServerError, err.Error())
          return
      }
 
      // 2. RouterOS all-paths (distance 20 via Synapsecom + distance 30 via GR-IX)
      if PathfinderROSClient != nil {
          ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
          defer cancel()
          rosRoutes, err := PathfinderROSClient.ListRoutesByPrefix(ctx, prefix)
          if err == nil {
              result.RouterOSPaths = rosRoutes  // add field to PrefixPaths struct
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
	asnName := r.URL.Query().Get("name") // optional enrichment passed from the UI

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

  func handleROSBGPSessions(w http.ResponseWriter, r *http.Request) {
      if PathfinderROSClient == nil {
          jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
          return
      }
      ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
      defer cancel()
      sessions, err := PathfinderROSClient.ListBGPSessions(ctx)
      if err != nil {
          jsonErr(w, http.StatusInternalServerError, err.Error())
          return
      }
      jsonOK(w, map[string]interface{}{
          "sessions": sessions,
          "summary":  routeros.Summarise(sessions),
      })
  }

//  func handleROSBGPPeers(w http.ResponseWriter, r *http.Request) { ... }
//  func handleROSRouterInfo(w http.ResponseWriter, r *http.Request) { ... }


