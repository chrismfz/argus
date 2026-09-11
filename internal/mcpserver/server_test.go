package mcpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testHandler builds the MCP handler with canned tool closures.
func testHandler() http.Handler {
	h := New(Deps{
		Version: "test",
		Tools: Tools{
			HostTraffic:   func(ip string, hours, top int) (any, error) { return map[string]any{"ip": ip, "hours": hours}, nil },
			TopLocalHosts: func(hours, top int) (any, error) { return map[string]any{"count": 1}, nil },
			InfoIP:        func(ip string) (any, error) { return map[string]any{"ip": ip}, nil },
			Interfaces:    func() (any, error) { return map[string]any{"eno1": 1}, nil },
			FlowSearch:    func(f FlowQuery) (any, error) { return map[string]any{"enabled": false}, nil },
		},
	})
	return h.HTTPHandler()
}

// rpc POSTs a JSON-RPC request the way cfm-web's FleetMcpClient does (stateless +
// JSON mode: a bare tools/list / tools/call with no initialize handshake, Accept
// listing both application/json and text/event-stream).
func rpc(t *testing.T, h http.Handler, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", method, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: decode: %v body=%s", method, err, rec.Body.String())
	}
	if e, ok := out["error"]; ok {
		t.Fatalf("%s: JSON-RPC error: %v", method, e)
	}
	return out
}

func TestToolsList(t *testing.T) {
	h := testHandler()
	out := rpc(t, h, "tools/list", map[string]any{})
	result, _ := out["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	got := map[string]bool{}
	for _, ti := range tools {
		if m, ok := ti.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				got[n] = true
			}
		}
	}
	for _, want := range []string{"host_traffic", "top_local_talkers", "infoip", "interfaces", "flow_search"} {
		if !got[want] {
			t.Errorf("tools/list missing %q (got %v)", want, got)
		}
	}
}

func TestToolsCallHostTraffic(t *testing.T) {
	h := testHandler()
	out := rpc(t, h, "tools/call", map[string]any{
		"name":      "host_traffic",
		"arguments": map[string]any{"ip": "84.54.49.202", "hours": 6},
	})
	result, _ := out["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in tools/call result: %v", out)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.Contains(text, "84.54.49.202") {
		t.Fatalf("host_traffic result did not carry the ip; text=%q", text)
	}
}

// A required-arg tool called with a blank arg must surface a tool error, not a
// silent empty success.
func TestToolsCallHostTrafficRequiresIP(t *testing.T) {
	h := testHandler()
	out := rpc(t, h, "tools/call", map[string]any{
		"name":      "host_traffic",
		"arguments": map[string]any{"ip": "  "},
	})
	result, _ := out["result"].(map[string]any)
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("expected isError=true for blank ip, got result=%v", result)
	}
}

// A nil closure must drop its tool from the advertised set (e.g. flow log off).
func TestNilClosureSkipsTool(t *testing.T) {
	h := New(Deps{Version: "test", Tools: Tools{
		HostTraffic: func(ip string, hours, top int) (any, error) { return map[string]any{}, nil },
	}}).HTTPHandler()
	out := rpc(t, h, "tools/list", map[string]any{})
	result, _ := out["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, ti := range tools {
		if m, ok := ti.(map[string]any); ok {
			if n, _ := m["name"].(string); n == "flow_search" || n == "interfaces" {
				t.Fatalf("tool %q should be absent when its closure is nil", n)
			}
		}
	}
}
