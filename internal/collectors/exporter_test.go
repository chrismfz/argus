package collectors

import (
	"net"
	"testing"
)

func TestExporterKeyDistinguishesIPv4Exporters(t *testing.T) {
	// net.UDPAddr hands IPv4 sources over in 16-byte form; the old code read its
	// first 4 bytes and keyed every IPv4 exporter's templates as 0.
	a := exporterKey(net.ParseIP("84.54.49.1"))
	b := exporterKey(net.ParseIP("84.54.49.2"))
	if a == 0 || b == 0 || a == b {
		t.Fatalf("exporterKey: %d / %d; want two distinct non-zero keys", a, b)
	}
	if a != exporterKey(net.IPv4(84, 54, 49, 1).To4()) {
		t.Fatal("4- and 16-byte forms of the same IPv4 must share a key")
	}
	v6a := exporterKey(net.ParseIP("2001:db8::1"))
	v6b := exporterKey(net.ParseIP("2001:db8::2"))
	if v6a == v6b {
		t.Fatal("IPv6 exporters must get distinct keys")
	}
}
