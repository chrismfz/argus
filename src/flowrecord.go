package main

import (
	"flowenricher/fields"
	"time"
)

type FlowRecord struct {
	TimestampStart       time.Time `ch:"timestamp_start"`
	TimestampEnd         time.Time `ch:"timestamp_end"`
	Proto                uint8     `ch:"proto"`
	TCPFlags             uint8     `ch:"tcpflags"`
	TOS                  uint8     `ch:"tos"`
	SrcHost              string    `ch:"src_host"`
	SrcPort              uint16    `ch:"src_port"`
	SrcHostCountry       string    `ch:"src_host_country"`
	DstHost              string    `ch:"dst_host"`
	DstPort              uint16    `ch:"dst_port"`
	DstHostCountry       string    `ch:"dst_host_country"`
	InputInterface       uint32    `ch:"input_interface"`
	OutputInterface      uint32    `ch:"output_interface"`
	NextHop              string    `ch:"next_hop"`
	PeerSrcAS            uint32    `ch:"peer_src_as"`
	PeerDstAS            uint32    `ch:"peer_dst_as"`
	ASPath               []string  `ch:"as_path"`
	LocalPref            uint32    `ch:"local_pref"`
	Packets              uint64    `ch:"packets"`
	Bytes                uint64    `ch:"bytes"`
	PeerDstASName        string    `ch:"peer_dst_as_name"`
	PeerSrcASName        string    `ch:"peer_src_as_name"`
	DstAS                uint32    `ch:"dst_as"`
	InputInterfaceName   string    `ch:"input_interface_name"`
	OutputInterfaceName  string    `ch:"output_interface_name"`
	FlowDirection        uint8     `ch:"flow_direction"`
	IPProtocol           uint8     `ch:"ip_protocol"`
}

func ConvertToFlowRecord(raw map[uint16]fields.Value) *FlowRecord {
	fr := &FlowRecord{}
	now := time.Now().UTC()

	// 🕒 Χρονισμός: Χρησιμοποίησε CUSTOM_TIMESTAMP αν υπάρχει (υπολογισμένο upstream μέσω calcTime)
	if v, ok := raw[fields.CUSTOM_TIMESTAMP]; ok {
		ts := time.Unix(int64(v.ToInt()), 0).UTC()
		fr.TimestampStart = ts
		fr.TimestampEnd = ts
	} else {
		fr.TimestampStart = now
		fr.TimestampEnd = now
	}

	// Πρωτόκολλο, σημαίες, TOS
	if v, ok := raw[fields.PROTOCOL]; ok {
		fr.Proto = uint8(v.ToInt())
	}
	if v, ok := raw[fields.TCP_FLAGS]; ok {
		fr.TCPFlags = uint8(v.ToInt())
	}
	if v, ok := raw[fields.SRC_TOS]; ok {
		fr.TOS = uint8(v.ToInt())
	}

	// Πηγή / Προορισμός IP
	if v, ok := raw[fields.IPV4_SRC_ADDR]; ok {
		fr.SrcHost = v.ToString()
	} else if v, ok := raw[fields.IPV6_SRC_ADDR]; ok {
		fr.SrcHost = v.ToString()
	}
	if v, ok := raw[fields.IPV4_DST_ADDR]; ok {
		fr.DstHost = v.ToString()
	} else if v, ok := raw[fields.IPV6_DST_ADDR]; ok {
		fr.DstHost = v.ToString()
	}

	// Πόρτες
	if v, ok := raw[fields.L4_SRC_PORT]; ok {
		fr.SrcPort = uint16(v.ToInt())
	}
	if v, ok := raw[fields.L4_DST_PORT]; ok {
		fr.DstPort = uint16(v.ToInt())
	}

	// Interfaces
	if v, ok := raw[fields.INPUT_SNMP]; ok {
		fr.InputInterface = uint32(v.ToInt())
	}
	if v, ok := raw[fields.OUTPUT_SNMP]; ok {
		fr.OutputInterface = uint32(v.ToInt())
	}

	// NextHop
	if v, ok := raw[fields.IPV4_NEXT_HOP]; ok {
		fr.NextHop = v.ToString()
	}

	// Packets & Bytes
	if v, ok := raw[fields.IN_PKTS]; ok {
		fr.Packets = uint64(v.ToInt())
	}
	if v, ok := raw[fields.IN_BYTES]; ok {
		fr.Bytes = uint64(v.ToInt())
	}

	// ASNs
	if v, ok := raw[fields.SRC_AS]; ok {
		fr.PeerSrcAS = uint32(v.ToInt())
	}
	if v, ok := raw[fields.DST_AS]; ok {
		asn := uint32(v.ToInt())
		fr.PeerDstAS = asn
		fr.DstAS = asn
	}

	// Flow direction
	if v, ok := raw[fields.FLOW_DIRECTION]; ok {
		fr.FlowDirection = uint8(v.ToInt())
	}

	// Enrichment fields (γεμίζουν αργότερα από enrichment layers)
	fr.SrcHostCountry = ""
	fr.DstHostCountry = ""
	fr.PeerSrcASName = ""
	fr.PeerDstASName = ""
	fr.ASPath = nil
	fr.LocalPref = 0
	fr.InputInterfaceName = ""
	fr.OutputInterfaceName = ""

	return fr
}
