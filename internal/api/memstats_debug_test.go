package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleMemStatsDebug(t *testing.T) {
	RegisterDebugComponent("testcomp", func() map[string]any {
		return map[string]any{"widgets": 7}
	})

	req := httptest.NewRequest(http.MethodGet, "/debug/memstats", nil)
	rec := httptest.NewRecorder()
	handleMemStatsDebug(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	gm, ok := res["go_mem"].(map[string]any)
	if !ok || gm["heap_inuse"] == nil {
		t.Fatalf("missing go_mem.heap_inuse: %v", res)
	}
	comps, ok := res["components"].(map[string]any)
	if !ok {
		t.Fatalf("missing components: %v", res)
	}
	// Nil-safe singletons: telemetry/flowstore/enrich Globals are unset in
	// tests — their entries must exist (possibly null) without panicking.
	tc, ok := comps["testcomp"].(map[string]any)
	if !ok || tc["widgets"] != float64(7) {
		t.Fatalf("registered component not reported: %v", comps)
	}
	if res["goroutines"] == nil || res["uptime_sec"] == nil {
		t.Fatalf("missing runtime fields: %v", res)
	}
}
