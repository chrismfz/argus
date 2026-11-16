package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/config"
)

// With nginx in front every request arrives from 127.0.0.1, and nginx appends
// the peer it saw to whatever X-Forwarded-For the client sent. Only that last
// entry may decide who the client is.
func TestRealIPIgnoresClientSuppliedForwardedFor(t *testing.T) {
	tests := []struct {
		name, remote string
		xff          []string
		want         string // "" = nil
	}{
		{"spoofed loopback, nginx appended the peer", "127.0.0.1:5000", []string{"127.0.0.1, 203.0.113.7"}, "203.0.113.7"},
		{"spoofed allowlisted address", "127.0.0.1:5000", []string{"10.0.0.5, 203.0.113.7"}, "203.0.113.7"},
		{"spoof on its own header line", "127.0.0.1:5000", []string{"127.0.0.1", "203.0.113.7"}, "203.0.113.7"},
		{"nginx overwrote the header", "127.0.0.1:5000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"local caller, no proxy", "127.0.0.1:5000", nil, "127.0.0.1"},
		{"unreadable proxy entry is nobody", "127.0.0.1:5000", []string{"127.0.0.1, junk"}, ""},
		{"direct remote client, header ignored", "203.0.113.7:5000", []string{"127.0.0.1"}, "203.0.113.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/status", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			got := realIP(r)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("realIP() = %v, want nil", got)
				}
				return
			}
			if got == nil || got.String() != tt.want {
				t.Fatalf("realIP() = %v, want %s", got, tt.want)
			}
		})
	}
}

// The whole point: a remote client behind nginx must not pass WithAuth by
// naming itself loopback or an allow_ips address.
func TestWithAuthRejectsSpoofedForwardedFor(t *testing.T) {
	prev := config.AppConfig
	config.AppConfig = &config.Config{}
	config.AppConfig.API.AllowIPs = []string{"10.0.0.5"}
	t.Cleanup(func() { config.AppConfig = prev })

	called := false
	h := WithAuth(func(w http.ResponseWriter, r *http.Request) { called = true })

	for _, spoof := range []string{"127.0.0.1", "::1", "10.0.0.5"} {
		called = false
		r := httptest.NewRequest(http.MethodPost, "/announce", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Forwarded-For", spoof+", 203.0.113.7") // what nginx forwards
		rec := httptest.NewRecorder()
		h(rec, r)
		if called || rec.Code != http.StatusForbidden {
			t.Fatalf("spoof %q: called=%v status=%d, want 403", spoof, called, rec.Code)
		}
	}

	// The allowlisted address itself, as nginx reports it, still passes.
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "10.0.0.5")
	h(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("allowlisted client behind nginx was rejected")
	}
}
