package flowdir

import (
	"net"
	"testing"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad CIDR %q: %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func TestClassify(t *testing.T) {
	upstream := []uint32{2, 3}
	myNets := mustNets(t, "84.54.49.0/24", "2a14:4280::/29")
	c := New(upstream, myNets)

	tests := []struct {
		name                         string
		inIface, outIface            uint32
		src, dst                     string
		fd                           uint8
		wantIn, wantSrcMy, wantDstMy bool
	}{
		// Tier 1: interface index wins, prefix flags stay false.
		{"input iface upstream => inbound", 2, 9, "84.54.49.10", "1.2.3.4", 0, true, false, false},
		{"output iface upstream => outbound", 9, 3, "1.2.3.4", "84.54.49.10", 0, false, false, false},
		{"iface index 0 is ignored", 0, 0, "84.54.49.10", "1.2.3.4", 0, false, true, false},
		// Tier 2: prefix matching when interfaces don't decide.
		{"dst in myNets => inbound", 9, 9, "1.2.3.4", "84.54.49.10", 1, true, false, true},
		{"src in myNets => outbound", 9, 9, "84.54.49.10", "1.2.3.4", 0, false, true, false},
		{"both in myNets => dst wins (inbound)", 9, 9, "84.54.49.11", "84.54.49.10", 1, true, true, true},
		{"ipv6 dst in myNets => inbound", 9, 9, "2001:db8::1", "2a14:4280::5", 1, true, false, true},
		// Tier 3: FlowDirection fallback when nothing else matches.
		{"no match, fd=0 => inbound", 9, 9, "1.2.3.4", "5.6.7.8", 0, true, false, false},
		{"no match, fd=1 => outbound", 9, 9, "1.2.3.4", "5.6.7.8", 1, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Classify("", tt.inIface, tt.outIface, tt.src, tt.dst, tt.fd)
			if got.Inbound != tt.wantIn || got.SrcInMy != tt.wantSrcMy || got.DstInMy != tt.wantDstMy {
				t.Fatalf("Classify(%d,%d,%q,%q,%d) = %+v; want {Inbound:%v SrcInMy:%v DstInMy:%v}",
					tt.inIface, tt.outIface, tt.src, tt.dst, tt.fd, got, tt.wantIn, tt.wantSrcMy, tt.wantDstMy)
			}
		})
	}
}

func TestClassifyNoUpstreamIfaces(t *testing.T) {
	// With no upstream interfaces configured, tier 1 is skipped entirely and
	// an interface that would otherwise match is ignored.
	c := New(nil, mustNets(t, "10.0.0.0/8"))
	got := c.Classify("", 2, 3, "1.2.3.4", "10.1.2.3", 1)
	if !got.Inbound || !got.DstInMy {
		t.Fatalf("expected inbound via prefix match, got %+v", got)
	}
}

func TestClassifyNoMyNets(t *testing.T) {
	// With no prefixes, tier 2 is skipped and it falls straight to FlowDirection.
	c := New([]uint32{2}, nil)
	if got := c.Classify("", 9, 9, "1.2.3.4", "5.6.7.8", 0); !got.Inbound {
		t.Fatalf("fd=0 should be inbound, got %+v", got)
	}
	if got := c.Classify("", 9, 9, "1.2.3.4", "5.6.7.8", 1); got.Inbound {
		t.Fatalf("fd=1 should be outbound, got %+v", got)
	}
}

func TestIsMyIP(t *testing.T) {
	c := New(nil, mustNets(t, "84.54.49.0/24"))
	if !c.IsMyIP("84.54.49.200") {
		t.Fatal("expected 84.54.49.200 to be local")
	}
	if c.IsMyIP("8.8.8.8") {
		t.Fatal("expected 8.8.8.8 not to be local")
	}
	if c.IsMyIP("not-an-ip") {
		t.Fatal("unparseable IP must not be local")
	}
}

func TestClassifyPerExporter(t *testing.T) {
	myNets := mustNets(t, "84.54.49.0/24")
	// R1 (84.54.49.1): sfp1/sfp2 = ifindex 2,3 are upstreams.
	// R2 (84.54.49.2): Cogent on ifindex 7; its ifindex 2 is a LAN port.
	c, err := NewWithExporters([]uint32{2, 3}, map[string][]uint32{
		"84.54.49.2": {7},
	}, myNets)
	if err != nil {
		t.Fatalf("NewWithExporters: %v", err)
	}

	// Remote → us, entering R2's Cogent port: tier 1 decides on R2's list.
	if got := c.Classify("84.54.49.2", 7, 2, "1.2.3.4", "84.54.49.10", 1); !got.Inbound || got.DstInMy {
		t.Fatalf("R2 upstream input: got %+v; want inbound by iface", got)
	}
	// On R2, ifindex 2 is NOT an upstream: an outbound flow leaving via R2's
	// Cogent port with input 2 must not be called inbound.
	if got := c.Classify("84.54.49.2", 2, 7, "84.54.49.10", "1.2.3.4", 0); got.Inbound {
		t.Fatalf("R2 ifindex 2 treated as upstream: got %+v", got)
	}
	// R1 is not listed → the default list still applies, as before.
	if got := c.Classify("84.54.49.1", 2, 9, "1.2.3.4", "84.54.49.10", 1); !got.Inbound || got.DstInMy {
		t.Fatalf("R1 default upstream: got %+v", got)
	}
	// Unknown exporter ("") also uses the default list.
	if got := c.Classify("", 9, 3, "84.54.49.10", "1.2.3.4", 0); got.Inbound {
		t.Fatalf("unknown exporter default upstream: got %+v", got)
	}
	// Exporter keys are canonicalised (IPv6 spelled differently still matches).
	c6, err := NewWithExporters(nil, map[string][]uint32{"2001:DB8::0001": {4}}, myNets)
	if err != nil {
		t.Fatalf("NewWithExporters v6: %v", err)
	}
	if got := c6.Classify("2001:db8::1", 4, 0, "1.2.3.4", "5.6.7.8", 1); !got.Inbound {
		t.Fatalf("v6 exporter key not canonicalised: got %+v", got)
	}

	if !c.CountsAsUpstream("84.54.49.2", 7) || c.CountsAsUpstream("84.54.49.2", 2) || !c.CountsAsUpstream("84.54.49.1", 3) {
		t.Fatal("CountsAsUpstream does not follow the per-exporter lists")
	}
	if !New(nil, nil).CountsAsUpstream("x", 42) {
		t.Fatal("with no upstreams configured every interface counts")
	}

	if _, err := NewWithExporters(nil, map[string][]uint32{"gw1-snc": {2}}, nil); err == nil {
		t.Fatal("a non-IP exporter key must be rejected")
	}
}
