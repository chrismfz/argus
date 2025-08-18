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
  // --- ΝΕΑ ---
    PostNATSrcIP       string    `ch:"post_nat_src_ip"`
    PostNATDstIP       string    `ch:"post_nat_dst_ip"`
    PostNATSrcPort     uint16    `ch:"post_nat_src_port"`
    PostNATDstPort     uint16    `ch:"post_nat_dst_port"`
}


func ConvertToFlowRecord(raw map[uint16]fields.Value) *FlowRecord {
    fr := &FlowRecord{}
    now := time.Now().UTC()

    // 🕒 timestamps (από CUSTOM_TIMESTAMP_START/CUSTOM_TIMESTAMP, με fallbacks)
    var tsStart, tsEnd time.Time
    if v, ok := raw[fields.CUSTOM_TIMESTAMP_START]; ok {
        tsStart = time.Unix(int64(v.ToInt()), 0).UTC()
    }
    if v, ok := raw[fields.CUSTOM_TIMESTAMP]; ok {
        tsEnd = time.Unix(int64(v.ToInt()), 0).UTC()
    }
    switch {
    case !tsStart.IsZero() && !tsEnd.IsZero():
        fr.TimestampStart, fr.TimestampEnd = tsStart, tsEnd
    case !tsStart.IsZero():
        fr.TimestampStart, fr.TimestampEnd = tsStart, tsStart
    case !tsEnd.IsZero():
        fr.TimestampStart, fr.TimestampEnd = tsEnd, tsEnd
    default:
        fr.TimestampStart, fr.TimestampEnd = now, now
    }

    // Πρωτόκολλο, σημαίες, TOS
    if v, ok := raw[fields.PROTOCOL]; ok {
        fr.Proto = uint8(v.ToInt())
        fr.IPProtocol = fr.Proto // γράψε και στο ip_protocol
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

    // Flow direction (⚠ δες σημείωση στο τέλος για το constant)
    if v, ok := raw[fields.DIRECTION]; ok { // <- χρησιμοποίησε DIRECTION
        fr.FlowDirection = uint8(v.ToInt())
    }

    // Post-NAT (Cisco/MikroTik 225..228)
    if v, ok := raw[225]; ok { fr.PostNATSrcIP = v.ToString() }
    if v, ok := raw[226]; ok { fr.PostNATDstIP = v.ToString() }
    if v, ok := raw[227]; ok { fr.PostNATSrcPort = uint16(v.ToInt()) }
    if v, ok := raw[228]; ok { fr.PostNATDstPort = uint16(v.ToInt()) }

    // Enrichment default values
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
