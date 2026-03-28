package api

import (
    "encoding/json"
    "net/http"
    "argus/internal/enrich"
)

func handleSNMPInterfaces(w http.ResponseWriter, r *http.Request) {
    stats, err := enrich.GetInterfaceTraffic(enrich.SNMPClient, enrich.IFNames)
    if err != nil {
        http.Error(w, "SNMP error: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(stats)
}
