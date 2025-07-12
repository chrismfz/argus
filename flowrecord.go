package main

import "time"

type FlowRecord struct {
	TimestampStart   time.Time
	Proto            uint8
	TCPFlags         uint8
	TOS              uint8
	SrcHost          string
	SrcPort          uint16
	SrcHostCountry   string
	DstHost          string
	DstPort          uint16
	DstHostCountry   string
	PeerSrcAS        uint32
	PeerDstAS        uint32
	ASPath           []string
	Packets          uint64
	Bytes            uint64
	PeerDstASName    string
	PeerSrcASName    string
	DstAS            uint32
	SrcHostPTR       string
	DstHostPTR       string
}
