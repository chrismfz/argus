package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"argus/internal/pathfinder"
)

// PathfinderResolver is initialised by main.go after the BGP server is ready.
var PathfinderResolver *pathfinder.Resolver

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
	result, err := PathfinderResolver.ResolvePrefix(prefix)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
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
