package api

import (
	_ "embed"
	"fmt"
	"net/http"

	"argus/internal/telemetry"
)

//go:embed static/flows_debug.html
var flowsDebugHTML []byte

// handleFlowsDebug serves the debug page HTML.
func handleFlowsDebug(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(flowsDebugHTML)
}

// handleFlowsStream is an SSE endpoint that streams live flows to the browser.
func handleFlowsStream(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if proxied

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send a keepalive comment immediately so the browser knows we're connected
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ch := telemetry.Tap.Subscribe()
	defer telemetry.Tap.Unsubscribe(ch)

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
