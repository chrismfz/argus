package bgp

import (
    "net"
)

type BGPEnrichedEntry struct {
    Net       net.IPNet  // 🟡 Παλιά ήταν: Network net.IPNet
    ASPath    []string
    LocalPref uint32
    ASN       uint32
    Communities []uint32
}

// ✅ Χρειάζεται για να ικανοποιεί το cidranger.RangerEntry
func (e BGPEnrichedEntry) Network() net.IPNet {
    return e.Net
}
