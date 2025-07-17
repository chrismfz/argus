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

/* useful fields for Mikrotik:


(10) INPUT_SNMP (Input Interface SNMP ifIndex) Add an InputInterface uint32  then typically map this ifIndex to a human-readable interface name (e.g., "ether1", "bridge-local") using SNMP lookups on your router.

(14) OUTPUT_SNMP (Output Interface SNMP ifIndex)

    What it is: The SNMP interface index of the interface where the flow exited the router.

    Why it's useful: Just like INPUT_SNMP, this is essential for knowing which interface traffic is leaving your router. It's vital for understanding traffic paths, egress bandwidth usage, and identifying potential bottlenecks.

    Recommendation: Add an OutputInterface uint32 (or uint16) field to your FlowRecord.


(15) IPV4_NEXT_HOP (IPv4 Next Hop Address)

    What it is: The IPv4 address of the next-hop router for the flow.

    Why it's useful: This provides crucial routing information. It tells you the immediate next router that the traffic was sent to. This is very valuable for tracing traffic paths, verifying routing decisions, and debugging connectivity issues.

    Recommendation: Add a NextHop string field to your FlowRecord.

(21) LAST_SWITCHED (Last Switched Timestamp)

    What it is: The system uptime in milliseconds when the last packet of this flow was observed.

    Why it's useful: While you have TimestampStart (derived from FIRST_SWITCHED or CUSTOM_TIMESTAMP), LAST_SWITCHED allows you to calculate the duration of the flow. This is important for understanding flow longevity, identifying long-lived connections (e.g., VPNs, large downloads), and detecting potential anomalies.

    Recommendation: You could add TimestampEnd time.Time to your FlowRecord and derive it similarly to TimestampStart, or add FlowDurationMs uint32 and calculate it from LAST_SWITCHED - FIRST_SWITCHED.


In short:
InputInterface
OutputInterface
NextHop

*/


