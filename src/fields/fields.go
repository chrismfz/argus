package fields

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
//	"math/big"
	"net"
)

// Value represents the interface to flowRecord Field values.
// Field values can be of many types but should always implement the same methods.
type Value interface {
	ToString() string
	SetType(uint16)
	ToInt() int
	ToBytes() []byte
}

// CONSTANTS
// Actual fields...
const IN_BYTES = 1
const IN_PKTS = 2
const FLOWS = 3
const PROTOCOL = 4
const SRC_TOS = 5 // Corrected: Cisco uses SRC_TOS for 5
const TCP_FLAGS = 6
const L4_SRC_PORT = 7
const IPV4_SRC_ADDR = 8
const SRC_MASK = 9
const INPUT_SNMP = 10
const L4_DST_PORT = 11
const IPV4_DST_ADDR = 12
const DST_MASK = 13
const OUTPUT_SNMP = 14
const IPV4_NEXT_HOP = 15
const SRC_AS = 16
const DST_AS = 17
const BGP_IPV4_NEXT_HOP = 18
const MUL_DST_PKTS = 19
const MUL_DST_BYTES = 20
const LAST_SWITCHED = 21
const FIRST_SWITCHED = 22
const OUT_BYTES = 23
const OUT_PKTS = 24
const MIN_PKT_LNGTH = 25
const MAX_PKT_LNGTH = 26
const IPV6_SRC_ADDR = 27
const IPV6_DST_ADDR = 28
const IPV6_SRC_MASK = 29
const IPV6_DST_MASK = 30
const IPV6_FLOW_LABEL = 31
const ICMP_TYPE = 32 // Corrected: Cisco uses ICMP_TYPE for 32
const MUL_IGMP_TYPE = 33
const SAMPLING_INTERVAL = 34
const SAMPLING_ALGORITHM = 35 // Corrected: Cisco uses SAMPLING_ALGORITHM for 35
const FLOW_ACTIVE_TIMEOUT = 36
const FLOW_INACTIVE_TIMEOUT = 37
const ENGINE_TYPE = 38
const ENGINE_ID = 39
const TOTAL_BYTES_EXP = 40
const TOTAL_PKTS_EXP = 41
const TOTAL_FLOWS_EXP = 42
const IPV4_SRC_PREFIX = 44
const IPV4_DST_PREFIX = 45
const MPLS_TOP_LABEL_TYPE = 46
const MPLS_TOP_LABEL_IP_ADDR = 47
const FLOW_SAMPLER_ID = 48
const FLOW_SAMPLER_MODE = 49
const FLOW_SAMPLER_RANDOM_INTERVAL = 50
const MIN_TTL = 52 // RFC defined
const MAX_TTL = 53 // RFC defined
const IPV4_IDENT = 54
const DST_TOS = 55
const IN_SRC_MAC = 56 // Corrected: Cisco uses IN_SRC_MAC for 56
const OUT_DST_MAC = 57 // Corrected: Cisco uses OUT_DST_MAC for 57
const SRC_VLAN = 58
const DST_VLAN = 59
const IP_PROTOCOL_VERSION = 60 // Corrected: Cisco uses IP_PROTOCOL_VERSION for 60
const DIRECTION = 61
const IPV6_NEXT_HOP = 62
const BPG_IPV6_NEXT_HOP = 63
const IPV6_OPTION_HEADERS = 64
const MPLS_LABEL_1 = 70
const MPLS_LABEL_2 = 71
const MPLS_LABEL_3 = 72
const MPLS_LABEL_4 = 73
const MPLS_LABEL_5 = 74
const MPLS_LABEL_6 = 75
const MPLS_LABEL_7 = 76
const MPLS_LABEL_8 = 77
const MPLS_LABEL_9 = 78
const MPLS_LABEL_10 = 79
const IN_DST_MAC = 80 // Corrected: Cisco uses IN_DST_MAC for 80
const OUT_SRC_MAC = 81 // Corrected: Cisco uses OUT_SRC_MAC for 81
const IF_NAME = 82
const IF_DESC = 83
const SAMPLER_NAME = 84
const IN_PERMANENT_BYTES = 85
const IN_PERMANENT_PKTS = 86
const FRAGMENT_OFFSET = 88
const FORWARDING_STATUS = 89
const MPLS_PAL_RD = 90
const MPLS_PREFIX_LEN = 91
const SRC_TRAFFIC_INDEX = 92
const DST_TRAFFIC_INDEX = 93
const APPLICATION_DESCRIPTION = 94 // Corrected: Cisco uses APPLICATION_DESCRIPTION for 94
const APPLICATION_TAG = 95
const APPLICATION_NAME = 96
const POST_IP_DIFF_SERV_CODE_POINT = 98
const REPLICATION_FACTOR = 99 // Corrected: Cisco uses REPLICATION_FACTOR for 99
const DEPRECATED = 100
const LAYER2_PACKET_SECTION_OFFSET = 102
const LAYER2_PACKET_SECTION_SIZE = 103
const LAYER2_PACKET_SECTION_DATA = 104 // Corrected: Cisco uses LAYER2_PACKET_SECTION_DATA for 104

// Aliases for common usage, matching user's previous code
const MIN_IP_TTL = MIN_TTL // Alias to resolve undefined error in netflow.go
const MAX_IP_TTL = MAX_TTL // Alias to resolve undefined error in netflow.go

// MikroTik/IPFIX Custom Fields (NAT related)
const POST_NAT_SOURCE_IPV4_ADDRESS = 225
const POST_NAT_DESTINATION_IPV4_ADDRESS = 226
const POST_NAPT_SOURCE_TRANSPORT_PORT = 227
const POST_NAPT_DESTINATION_TRANSPORT_PORT = 228

// Common IPFIX fields (might be vendor-specific in Netflow v9)
const FIREWALL_EVENT = 233 // Kept as a common IPFIX field, but not 80 in Cisco Netflow v9

// Extension fields (your custom timestamp)
const CUSTOM_TIMESTAMP = 256 // New ID for your custom timestamp to avoid conflict with REPLICATION_FACTOR (99)

// Integer Values
type IntValue struct {
	Data  int
	Type  uint16
	Bytes []byte
}

func (i IntValue) SetType(t uint16) {
	i.Type = t
}
func (i IntValue) ToString() string {
	return fmt.Sprintf("%v", i.Data)
}

func (i IntValue) ToInt() int {
	return i.Data
}
func (i IntValue) ToBytes() []byte {
	return i.Bytes
}

// Retrieve integer values from a field
func GetInt(p []byte) Value {
	var i IntValue
	i.Bytes = p
	switch {
	case len(p) >= 4: // Use >= for robustness with N-byte fields
		i.Data = int(binary.BigEndian.Uint32(p))
		return i
	case len(p) >= 2:
		i.Data = int(binary.BigEndian.Uint16(p))
		return i
	case len(p) >= 1:
		i.Data = int(uint8(p[0]))
		return i
	default:
		return IntValue{Data: 0, Bytes: p} // Return a zero value for empty slices
	}
}

// Address Values (IPv4)
type AddrValue struct {
	Data  net.IP
	Type  uint16
	Int   uint32
	Bytes []byte
}

func (i AddrValue) ToInt() int {
	return int(i.Int)
}

func (i AddrValue) SetType(t uint16) {
	i.Type = t
}
func (a AddrValue) ToString() string {
	return fmt.Sprintf("%v", a.Data.String())
}

func (a AddrValue) ToBytes() []byte {
	return a.Bytes
}

// Retrieve an IPv4 address value from a field
func GetAddr(p []byte) Value {
	var a AddrValue
	if len(p) >= 4 { // Ensure enough bytes for an IPv4 address
		a.Data = net.IP(p)
		a.Int = binary.BigEndian.Uint32(p)
	} else {
		a.Data = net.IPv4zero // Default to zero IP if not enough bytes
		a.Int = 0
	}
	a.Bytes = p
	return a
}


// Address Values (IPv6)
type Addr6Value struct {
	Data  string
	Type  uint16
	Int   net.IP // This field is problematic for IPv6, as net.IP is 16 bytes
	Bytes []byte
}

func (i Addr6Value) ToInt() int {
	// V6 addresses don't fit in a 64-bit UINT so this function is uncallable
	return 0
}

func (i Addr6Value) SetType(t uint16) {
	i.Type = t
}
func (a Addr6Value) ToString() string {
	// For IPv6, it's better to use net.IP(a.Bytes).String() if a.Bytes is 16 bytes
	// or format the hex string.
	if len(a.Bytes) == 16 {
		return net.IP(a.Bytes).String()
	}
	return fmt.Sprintf("%v", a.Data) // Fallback to hex string if not 16 bytes
}

func (a Addr6Value) ToBytes() []byte {
	return a.Bytes
}

// Retrieve an IPv6 address value from a field
func GetAddr6(p []byte) Value {
	var a Addr6Value
	if len(p) == 16 { // IPv6 addresses are 16 bytes
		a.Bytes = p
		a.Data = net.IP(p).String() // Store as string for ToString()
	} else {
		// Handle cases where IPv6 address might not be 16 bytes (e.g., truncated)
		// For now, store as hex string, or log error
		a.Bytes = p
		a.Data = hex.EncodeToString(p)
	}
	// Note: Int field is not suitable for IPv6 addresses
	return a
}

// String Values
type StringValue struct {
	Data  string
	Type  uint16
	Bytes []byte
}

func (s StringValue) SetType(t uint16) {
	s.Type = t
}
func (s StringValue) ToString() string {
	return s.Data
}
func (s StringValue) ToInt() int {
	// Strings don't convert directly to int, return 0 or error if needed
	return 0
}
func (s StringValue) ToBytes() []byte {
	return s.Bytes
}

// Retrieve string values from a field
func GetString(p []byte) Value {
	var s StringValue
	s.Data = string(p)
	s.Bytes = p
	return s
}

// MAC Address Values
type MacValue struct {
	Data  net.HardwareAddr
	Type  uint16
	Bytes []byte
}

func (m MacValue) SetType(t uint16) {
	m.Type = t
}
func (m MacValue) ToString() string {
	return m.Data.String()
}
func (m MacValue) ToInt() int {
	// MAC addresses don't convert directly to int
	return 0
}
func (m MacValue) ToBytes() []byte {
	return m.Bytes
}

// Retrieve MAC address values from a field
func GetMac(p []byte) Value {
	var m MacValue
	if len(p) == 6 { // MAC addresses are 6 bytes
		m.Data = net.HardwareAddr(p)
	} else {
		// Handle unexpected length, maybe log a warning
		m.Data = make(net.HardwareAddr, 6) // Zero-filled MAC
	}
	m.Bytes = p
	return m
}

// Raw Bytes Value (for fields like LAYER2_PACKET_SECTION_DATA)
type BytesValue struct {
	Data  []byte
	Type  uint16
	Bytes []byte
}

func (b BytesValue) SetType(t uint16) {
	b.Type = t
}
func (b BytesValue) ToString() string {
	return hex.EncodeToString(b.Data) // Represent as hex string
}
func (b BytesValue) ToInt() int {
	// Raw bytes don't convert directly to int
	return 0
}
func (b BytesValue) ToBytes() []byte {
	return b.Bytes
}

// Retrieve raw bytes values from a field
func GetBytes(p []byte) Value {
	return BytesValue{Data: p, Bytes: p}
}

