package api

import (
	_ "embed"
	"fmt"
	"net/http"

	"argus/internal/telemetry"
)

//go:embed static/rawflows_debug.html
var rawFlowsDebugHTML []byte

func handleRawFlowsDebug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(rawFlowsDebugHTML)
}

func handleRawFlowsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ch := telemetry.RawTap.Subscribe()
	defer telemetry.RawTap.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			w.Write(line)
			flusher.Flush()
		}
	}
}
