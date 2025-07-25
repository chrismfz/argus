package main

import (
	"flowenricher/fields"
	"time"
)

type FlowRecord struct {
        TimestampStart   time.Time  `ch:"timestamp_start"`
        TimestampEnd     time.Time  `ch:"timestamp_end"` // New field for LAST_SWITCHED
        Proto            uint8      `ch:"proto"`
        TCPFlags         uint8      `ch:"tcpflags"`
        TOS              uint8      `ch:"tos"`
        SrcHost          string     `ch:"src_host"`
        SrcPort          uint16     `ch:"src_port"`
        SrcHostCountry   string     `ch:"src_host_country"`
        DstHost          string     `ch:"dst_host"`
        DstPort          uint16     `ch:"dst_port"`
        DstHostCountry   string     `ch:"dst_host_country"`
        InputInterface   uint32     `ch:"input_interface"`  // New field for INPUT_SNMP
        OutputInterface  uint32     `ch:"output_interface"` // New field for OUTPUT_SNMP
        NextHop          string     `ch:"next_hop"`         // New field for IPV4_NEXT_HOP
        PeerSrcAS        uint32     `ch:"peer_src_as"`
        PeerDstAS        uint32     `ch:"peer_dst_as"`
        ASPath           []string   `ch:"as_path"`
	LocalPref 	 uint32     `ch:"local_pref"`
        Packets          uint64     `ch:"packets"`
        Bytes            uint64     `ch:"bytes"`
        PeerDstASName    string     `ch:"peer_dst_as_name"`
        PeerSrcASName    string     `ch:"peer_src_as_name"`
        DstAS            uint32     `ch:"dst_as"`
	InputInterfaceName   string `ch:"input_interface_name"`
	OutputInterfaceName  string `ch:"output_interface_name"`
	FlowDirection        uint8  `ch:"flow_direction"`
	IPProtocol           uint8  `ch:"ip_protocol"`
}


func ConvertToFlowRecord(raw map[uint16]fields.Value) *FlowRecord {
	fr := &FlowRecord{}

	// Prioritize LAST_SWITCHED or FIRST_SWITCHED for accurate flow time
	// Use blank identifier '_' for tsVal where its value is not directly used
	if _, ok := raw[fields.LAST_SWITCHED]; ok {
		// Netflow v9 Uptime is in milliseconds, LAST_SWITCHED is in milliseconds relative to Uptime
		// The calcTime in netflow.go already converts this to an absolute Unix timestamp.
		// We just need to use that CUSTOM_TIMESTAMP field.
		if customTsVal, customTsOk := raw[fields.CUSTOM_TIMESTAMP]; customTsOk {
			fr.TimestampStart = time.Unix(int64(customTsVal.ToInt()), 0).UTC()
			fr.TimestampEnd = fr.TimestampStart // For now, assume end is same as start if no explicit end time
		} else {
			// Fallback if CUSTOM_TIMESTAMP wasn't set by calcTime (shouldn't happen if calcTime is called)
			now := time.Now().UTC()
			fr.TimestampStart = now
			fr.TimestampEnd = now
		}
	} else if _, ok := raw[fields.FIRST_SWITCHED]; ok {
		// Handle FIRST_SWITCHED if LAST_SWITCHED is not available
		if customTsVal, customTsOk := raw[fields.CUSTOM_TIMESTAMP]; customTsOk {
			fr.TimestampStart = time.Unix(int64(customTsVal.ToInt()), 0).UTC()
			fr.TimestampEnd = fr.TimestampStart
		} else {
			now := time.Now().UTC()
			fr.TimestampStart = now
			fr.TimestampEnd = now
		}
	} else if tsVal, ok := raw[fields.CUSTOM_TIMESTAMP]; ok {
		// If only CUSTOM_TIMESTAMP is directly available
		fr.TimestampStart = time.Unix(int64(tsVal.ToInt()), 0).UTC()
		fr.TimestampEnd = fr.TimestampStart
	} else {
		// Default to current time if no flow timestamp is available
		now := time.Now().UTC()
		fr.TimestampStart = now
		fr.TimestampEnd = now
	}


	// Πρωτόκολλο, σημαίες, tos
	if v, ok := raw[fields.PROTOCOL]; ok {
		fr.Proto = uint8(v.ToInt())
	}
	if v, ok := raw[fields.TCP_FLAGS]; ok {
		fr.TCPFlags = uint8(v.ToInt())
	}
	if v, ok := raw[fields.SRC_TOS]; ok {
		fr.TOS = uint8(v.ToInt())
	}

	// Πηγές και προορισμοί (IPv4 ή IPv6)
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

//Interface In ID
if v, ok := raw[fields.INPUT_SNMP]; ok {
    fr.InputInterface = uint32(v.ToInt())
}
//Interface Out ID
if v, ok := raw[fields.OUTPUT_SNMP]; ok {
    fr.OutputInterface = uint32(v.ToInt())
}
//Flow direction (1/0)
if v, ok := raw[fields.FLOW_DIRECTION]; ok {
    fr.FlowDirection = uint8(v.ToInt())
}
//IP Protocol
if v, ok := raw[fields.IP_PROTOCOL_VERSION]; ok {
    fr.IPProtocol = uint8(v.ToInt())
}


	// Το enrichment (GeoIP / PTR / ASPath) θα το κάνεις ξεχωριστά από το batcher.

	return fr
}

