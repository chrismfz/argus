package api

import (
        "context"
        "net/http"
        "time"

        "argus/internal/routeros"
)

// GET /routeros/bgp/sessions
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

// GET /routeros/bgp/peers
func handleROSBGPPeers(w http.ResponseWriter, r *http.Request) {
        if PathfinderROSClient == nil {
                jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
                return
        }
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        peers, err := PathfinderROSClient.ListBGPPeers(ctx)
        if err != nil {
                jsonErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        jsonOK(w, peers)
}

// GET /routeros/router/info
func handleROSRouterInfo(w http.ResponseWriter, r *http.Request) {
        if PathfinderROSClient == nil {
                jsonErr(w, http.StatusServiceUnavailable, "RouterOS not connected")
                return
        }
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        info, err := PathfinderROSClient.GetRouterInfo(ctx)
        if err != nil {
                jsonErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        jsonOK(w, info)
}
