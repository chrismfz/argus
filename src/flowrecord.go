package main

import "time"

type FlowRecord struct {
        TimestampStart   time.Time  `ch:"timestamp_start"`
        Proto            uint8      `ch:"proto"`
        TCPFlags         uint8      `ch:"tcpflags"`
        TOS              uint8      `ch:"tos"`
        SrcHost          string     `ch:"src_host"`
        SrcPort          uint16     `ch:"src_port"`
        SrcHostCountry   string     `ch:"src_host_country"`
        DstHost          string     `ch:"dst_host"`
        DstPort          uint16     `ch:"dst_port"`
        DstHostCountry   string     `ch:"dst_host_country"`
        PeerSrcAS        uint32     `ch:"peer_src_as"`
        PeerDstAS        uint32     `ch:"peer_dst_as"`
        ASPath           []string   `ch:"as_path"`
	LocalPref 	 uint32     `ch:"local_pref"`
        Packets          uint64     `ch:"packets"`
        Bytes            uint64     `ch:"bytes"`
        PeerDstASName    string     `ch:"peer_dst_as_name"`
        PeerSrcASName    string     `ch:"peer_src_as_name"`
        DstAS            uint32     `ch:"dst_as"`
        SrcHostPTR       string     `ch:"src_host_ptr"`
        DstHostPTR       string     `ch:"dst_host_ptr"`
}
