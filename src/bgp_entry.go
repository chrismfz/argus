package main

import (
    "net"

//    "github.com/yl2chen/cidranger"
)

type BGPEnrichedEntry struct {
    network    net.IPNet
    ASPath     []string
    LocalPref  uint32
}

func (e BGPEnrichedEntry) Network() net.IPNet {
    return e.network
}
