package collectors

import (
	"encoding/binary"
	"fmt"
	"flowenricher/fields"
	"io" // Import for io.Writer
	"log" // Import for logging
	"net"
	"os"
	"strconv"
	"strings"
)

type Frontend interface {
	Start()
	Configure(config map[string]string)
}

// CONSTANTS (remain the same, as they are imported from fields.go)
const IN_BYTES = fields.IN_BYTES
const IN_PKTS = fields.IN_PKTS
const FLOWS = fields.FLOWS
const PROTOCOL = fields.PROTOCOL
const SRC_TOS = fields.SRC_TOS
const TCP_FLAGS = fields.TCP_FLAGS
const L4_SRC_PORT = fields.L4_SRC_PORT
const IPV4_SRC_ADDR = fields.IPV4_SRC_ADDR
const SRC_MASK = fields.SRC_MASK
const INPUT_SNMP = fields.INPUT_SNMP
const L4_DST_PORT = fields.L4_DST_PORT
const IPV4_DST_ADDR = fields.IPV4_DST_ADDR
const DST_MASK = fields.DST_MASK
const OUTPUT_SNMP = fields.OUTPUT_SNMP
const IPV4_NEXT_HOP = fields.IPV4_NEXT_HOP
const OUT_BYTES = fields.OUT_BYTES
const OUT_PKTS = fields.OUT_PKTS
const LAST_SWITCHED = fields.LAST_SWITCHED
const IPV6_SRC_ADDR = fields.IPV6_SRC_ADDR
const IPV6_DST_ADDR = fields.IPV6_DST_ADDR

// New fields added (from fields.go)
const SRC_AS = fields.SRC_AS
const DST_AS = fields.DST_AS
const BGP_IPV4_NEXT_HOP = fields.BGP_IPV4_NEXT_HOP
const FIRST_SWITCHED = fields.FIRST_SWITCHED
const MIN_PKT_LNGTH = fields.MIN_PKT_LNGTH
const MAX_PKT_LNGTH = fields.MAX_PKT_LNGTH
const MIN_IP_TTL = fields.MIN_IP_TTL // Now correctly aliased in fields.go
const MAX_IP_TTL = fields.MAX_IP_TTL // Now correctly aliased in fields.go
const SAMPLING_INTERVAL = fields.SAMPLING_INTERVAL
const ICMP_TYPE = fields.ICMP_TYPE
const MUL_IGMP_TYPE = fields.MUL_IGMP_TYPE
const SAMPLING_ALGORITHM = fields.SAMPLING_ALGORITHM
const FLOW_ACTIVE_TIMEOUT = fields.FLOW_ACTIVE_TIMEOUT
const FLOW_INACTIVE_TIMEOUT = fields.FLOW_INACTIVE_TIMEOUT
const ENGINE_TYPE = fields.ENGINE_TYPE
const ENGINE_ID = fields.ENGINE_ID
const TOTAL_BYTES_EXP = fields.TOTAL_BYTES_EXP
const TOTAL_PKTS_EXP = fields.TOTAL_PKTS_EXP
const TOTAL_FLOWS_EXP = fields.TOTAL_FLOWS_EXP
const IPV4_SRC_PREFIX = fields.IPV4_SRC_PREFIX
const IPV4_DST_PREFIX = fields.IPV4_DST_PREFIX
const MPLS_TOP_LABEL_TYPE = fields.MPLS_TOP_LABEL_TYPE
const MPLS_TOP_LABEL_IP_ADDR = fields.MPLS_TOP_LABEL_IP_ADDR
const FLOW_SAMPLER_ID = fields.FLOW_SAMPLER_ID
const FLOW_SAMPLER_MODE = fields.FLOW_SAMPLER_MODE
const FLOW_SAMPLER_RANDOM_INTERVAL = fields.FLOW_SAMPLER_RANDOM_INTERVAL
const MIN_TTL = fields.MIN_TTL
const MAX_TTL = fields.MAX_TTL
const IPV4_IDENT = fields.IPV4_IDENT
const DST_TOS = fields.DST_TOS
const IN_SRC_MAC = fields.IN_SRC_MAC
const OUT_DST_MAC = fields.OUT_DST_MAC
const SRC_VLAN = fields.SRC_VLAN
const DST_VLAN = fields.DST_VLAN
const IP_PROTOCOL_VERSION = fields.IP_PROTOCOL_VERSION
const DIRECTION = fields.DIRECTION
const IPV6_NEXT_HOP = fields.IPV6_NEXT_HOP
const BPG_IPV6_NEXT_HOP = fields.BPG_IPV6_NEXT_HOP
const IPV6_OPTION_HEADERS = fields.IPV6_OPTION_HEADERS
const MPLS_LABEL_1 = fields.MPLS_LABEL_1
const MPLS_LABEL_2 = fields.MPLS_LABEL_2
const MPLS_LABEL_3 = fields.MPLS_LABEL_3
const MPLS_LABEL_4 = fields.MPLS_LABEL_4
const MPLS_LABEL_5 = fields.MPLS_LABEL_5
const MPLS_LABEL_6 = fields.MPLS_LABEL_6
const MPLS_LABEL_7 = fields.MPLS_LABEL_7
const MPLS_LABEL_8 = fields.MPLS_LABEL_8
const MPLS_LABEL_9 = fields.MPLS_LABEL_9
const MPLS_LABEL_10 = fields.MPLS_LABEL_10
const IN_DST_MAC = fields.IN_DST_MAC
const OUT_SRC_MAC = fields.OUT_SRC_MAC
const IF_NAME = fields.IF_NAME
const IF_DESC = fields.IF_DESC
const SAMPLER_NAME = fields.SAMPLER_NAME
const IN_PERMANENT_BYTES = fields.IN_PERMANENT_BYTES
const IN_PERMANENT_PKTS = fields.IN_PERMANENT_PKTS
const FRAGMENT_OFFSET = fields.FRAGMENT_OFFSET
const FORWARDING_STATUS = fields.FORWARDING_STATUS
const MPLS_PAL_RD = fields.MPLS_PAL_RD
const MPLS_PREFIX_LEN = fields.MPLS_PREFIX_LEN
const SRC_TRAFFIC_INDEX = fields.SRC_TRAFFIC_INDEX
const DST_TRAFFIC_INDEX = fields.DST_TRAFFIC_INDEX
const APPLICATION_DESCRIPTION = fields.APPLICATION_DESCRIPTION
const APPLICATION_TAG = fields.APPLICATION_TAG
const APPLICATION_NAME = fields.APPLICATION_NAME
const POST_IP_DIFF_SERV_CODE_POINT = fields.POST_IP_DIFF_SERV_CODE_POINT
const REPLICATION_FACTOR = fields.REPLICATION_FACTOR
const DEPRECATED = fields.DEPRECATED
const LAYER2_PACKET_SECTION_OFFSET = fields.LAYER2_PACKET_SECTION_OFFSET
const LAYER2_PACKET_SECTION_SIZE = fields.LAYER2_PACKET_SECTION_SIZE
const LAYER2_PACKET_SECTION_DATA = fields.LAYER2_PACKET_SECTION_DATA
const FIREWALL_EVENT = fields.FIREWALL_EVENT

// MikroTik/IPFIX Custom Fields (NAT related)
const POST_NAT_SOURCE_IPV4_ADDRESS = fields.POST_NAT_SOURCE_IPV4_ADDRESS
const POST_NAT_DESTINATION_IPV4_ADDRESS = fields.POST_NAT_DESTINATION_IPV4_ADDRESS
const POST_NAPT_SOURCE_TRANSPORT_PORT = fields.POST_NAPT_SOURCE_TRANSPORT_PORT
const POST_NAPT_DESTINATION_TRANSPORT_PORT = fields.POST_NAPT_DESTINATION_TRANSPORT_PORT


// Extension fields
const _TIMESTAMP = fields.CUSTOM_TIMESTAMP // Now using your new custom timestamp ID

var FUNCTIONMAP = map[uint16]func([]byte) fields.Value{
	IN_BYTES:             fields.GetInt,
	IN_PKTS:              fields.GetInt,
	FLOWS:                fields.GetInt,
	PROTOCOL:             fields.GetInt,
	SRC_TOS:              fields.GetInt,
	TCP_FLAGS:            fields.GetInt,
	L4_SRC_PORT:          fields.GetInt,
	IPV4_SRC_ADDR:        fields.GetAddr,
	SRC_MASK:             fields.GetInt,
	INPUT_SNMP:           fields.GetInt,
	L4_DST_PORT:          fields.GetInt,
	IPV4_DST_ADDR:        fields.GetAddr,
	DST_MASK:             fields.GetInt,
	OUTPUT_SNMP:          fields.GetInt,
	IPV4_NEXT_HOP:        fields.GetAddr,
	OUT_BYTES:            fields.GetInt,
	OUT_PKTS:             fields.GetInt,
	LAST_SWITCHED:        fields.GetInt,
	IPV6_SRC_ADDR:        fields.GetAddr6,
	IPV6_DST_ADDR:        fields.GetAddr6,
	SRC_AS:                 fields.GetInt,
	DST_AS:                 fields.GetInt,
	BGP_IPV4_NEXT_HOP:      fields.GetAddr,
	FIRST_SWITCHED:         fields.GetInt,
	MIN_PKT_LNGTH:          fields.GetInt,
	MAX_PKT_LNGTH:          fields.GetInt,
	MIN_TTL:                fields.GetInt,
	MAX_TTL:                fields.GetInt,
	SAMPLING_INTERVAL:      fields.GetInt,
	ICMP_TYPE:              fields.GetInt,
	MUL_IGMP_TYPE:          fields.GetInt,
	SAMPLING_ALGORITHM:     fields.GetInt,
	FLOW_ACTIVE_TIMEOUT:    fields.GetInt,
	FLOW_INACTIVE_TIMEOUT:  fields.GetInt,
	ENGINE_TYPE:            fields.GetInt,
	ENGINE_ID:              fields.GetInt,
	TOTAL_BYTES_EXP:        fields.GetInt,
	TOTAL_PKTS_EXP:         fields.GetInt,
	TOTAL_FLOWS_EXP:        fields.GetInt,
	IPV4_SRC_PREFIX:        fields.GetAddr,
	IPV4_DST_PREFIX:        fields.GetAddr,
	MPLS_TOP_LABEL_TYPE:    fields.GetInt,
	MPLS_TOP_LABEL_IP_ADDR: fields.GetAddr,
	FLOW_SAMPLER_ID:        fields.GetInt,
	FLOW_SAMPLER_MODE:      fields.GetInt,
	FLOW_SAMPLER_RANDOM_INTERVAL: fields.GetInt,
	IPV4_IDENT:             fields.GetInt,
	DST_TOS:                fields.GetInt,
	IN_SRC_MAC:             fields.GetMac,
	OUT_DST_MAC:            fields.GetMac,
	SRC_VLAN:               fields.GetInt,
	DST_VLAN:               fields.GetInt,
	IP_PROTOCOL_VERSION:    fields.GetInt,
	DIRECTION:              fields.GetInt,
	IPV6_NEXT_HOP:          fields.GetAddr6,
	BPG_IPV6_NEXT_HOP:      fields.GetAddr6,
	IPV6_OPTION_HEADERS:    fields.GetInt,
	MPLS_LABEL_1:           fields.GetInt,
	MPLS_LABEL_2:           fields.GetInt,
	MPLS_LABEL_3:           fields.GetInt,
	MPLS_LABEL_4:           fields.GetInt,
	MPLS_LABEL_5:           fields.GetInt,
	MPLS_LABEL_6:           fields.GetInt,
	MPLS_LABEL_7:           fields.GetInt,
	MPLS_LABEL_8:           fields.GetInt,
	MPLS_LABEL_9:           fields.GetInt,
	MPLS_LABEL_10:          fields.GetInt,
	IN_DST_MAC:             fields.GetMac,
	OUT_SRC_MAC:            fields.GetMac,
	IF_NAME:                fields.GetString,
	IF_DESC:                fields.GetString,
	SAMPLER_NAME:           fields.GetString,
	IN_PERMANENT_BYTES:     fields.GetInt,
	IN_PERMANENT_PKTS:      fields.GetInt,
	FRAGMENT_OFFSET:        fields.GetInt,
	FORWARDING_STATUS:      fields.GetInt,
	MPLS_PAL_RD:            fields.GetBytes,
	MPLS_PREFIX_LEN:        fields.GetInt,
	SRC_TRAFFIC_INDEX:      fields.GetInt,
	DST_TRAFFIC_INDEX:      fields.GetInt,
	APPLICATION_DESCRIPTION: fields.GetString,
	APPLICATION_TAG:        fields.GetInt,
	APPLICATION_NAME:       fields.GetString,
	POST_IP_DIFF_SERV_CODE_POINT: fields.GetInt,
	REPLICATION_FACTOR:     fields.GetInt,
	DEPRECATED:             fields.GetBytes,
	LAYER2_PACKET_SECTION_OFFSET: fields.GetInt,
	LAYER2_PACKET_SECTION_SIZE: fields.GetInt,
	LAYER2_PACKET_SECTION_DATA: fields.GetBytes,
	FIREWALL_EVENT:         fields.GetInt,
	POST_NAT_SOURCE_IPV4_ADDRESS: fields.GetAddr,
	POST_NAT_DESTINATION_IPV4_ADDRESS: fields.GetAddr,
	POST_NAPT_SOURCE_TRANSPORT_PORT: fields.GetInt,
	POST_NAPT_DESTINATION_TRANSPORT_PORT: fields.GetInt,
	_TIMESTAMP:             fields.GetInt,
}

//
// GENERICS
//
// Netflow listener and main object
type Netflow struct {
	Templates   map[uint32]map[uint32]map[uint16]netflowPacketTemplate
	BindAddr    net.IP
	BindPort    int
	debug       bool
	FlowChannel chan map[uint16]fields.Value
	logger      *log.Logger // New logger field
	logFile     *os.File    // To hold the file handle if logging to file
}
type netflowPacket struct {
	Source    uint32
	Header    netflowPacketHeader
	Length    int
	Templates map[uint32]map[uint32]map[uint16]netflowPacketTemplate
	Data      []netflowDataFlowset
}
type netflowPacketHeader struct {
	Version  uint16
	Count    uint16
	Uptime   uint32
	Usecs    uint32
	Sequence uint32
	Id       uint32
}
type netflowPacketFlowset struct {
	FlowSetID uint16
	Length    uint16
}

// TEMPLATE STRUCTS (remain the same)
type netflowPacketTemplate struct {
	FlowSetID   uint16
	Length      uint16
	ID          uint16
	FieldCount  uint16
	Fields      []templateField
	FieldLength uint16
}
type templateField struct {
	FieldType uint16
	Length    uint16
}

// DATA STRUCTS (remain the same)
type netflowDataFlowset struct {
	FlowSetID uint16
	Length    uint16
	Records   []flowRecord
}
type flowRecord struct {
	Values    []fields.Value
	ValuesMap map[uint16]fields.Value
}

func (r *flowRecord) calcTime(s uint32, u uint32) uint32 {
	var ts uint32

	if flowendSecs, ok := r.ValuesMap[LAST_SWITCHED]; ok {
		ts = u - (s / 1000) + (uint32(flowendSecs.ToInt()) / 1000)
		v := fields.IntValue{Data: int(ts)}
		r.ValuesMap[fields.CUSTOM_TIMESTAMP] = v // Use CUSTOM_TIMESTAMP here
	}
	return ts
}
func (r flowRecord) toString() string {
	var sl []string
	for _, v := range r.Values {
		sl = append(sl, v.ToString())
	}
	return strings.Join(sl, " : ") + "\n"
}

/*
ParseData

Takes a slice of a data flowset and retreives all the flow records
Requires
	n netflowPacket : Netflow packet struct (for templates)
	p []byte : Data Flowset slice
	logger *log.Logger : Logger instance for warnings
*/
func parseData(n netflowPacket, p []byte, logger *log.Logger) netflowDataFlowset {
	nfd := netflowDataFlowset{
		FlowSetID: binary.BigEndian.Uint16(p[:2]),
		Length:    binary.BigEndian.Uint16(p[2:4]),
	}

	// If we have no template for this source IP
	if _, ok := n.Templates[n.Source]; !ok {
		logger.Printf("Warning: No templates for source IP %d. Skipping data flowset.\n", n.Source)
		return nfd
	} else {
		// If we have no templates for this source "ID"
		if _, ok := n.Templates[n.Source][n.Header.Id]; !ok {
			logger.Printf("Warning: No templates for source ID %d from IP %d. Skipping data flowset.\n", n.Header.Id, n.Source)
			return nfd
		} else {
			// Finally, if we have no template ID matching the flowset.
			if _, ok := n.Templates[n.Source][n.Header.Id][nfd.FlowSetID]; !ok {
				logger.Printf("Warning: No template ID %d for source ID %d from IP %d. Skipping data flowset.\n", nfd.FlowSetID, n.Header.Id, n.Source)
				return nfd
			}
		}
	}

	t := n.Templates[n.Source][n.Header.Id][nfd.FlowSetID]

	start := uint16(4)
	// Read each Field in order from the flowset until the length is exceeded
	for start < nfd.Length {
		// Check the number of fields don't overrun the size of this flowset
		// if so, remainder must be padding
		if t.FieldLength <= (nfd.Length - start) {
			fr := flowRecord{ValuesMap: make(map[uint16]fields.Value)}
			for _, f := range t.Fields {
				valueSlice := p[start : start+f.Length]
				if function, ok := FUNCTIONMAP[f.FieldType]; ok {
					value := function(valueSlice)
					value.SetType(f.FieldType)
					fr.Values = append(fr.Values, value)
					fr.ValuesMap[f.FieldType] = value
				} else {
					// Log a warning for unknown field types
					logger.Printf("Warning: Unknown Netflow field type %d encountered. Skipping.\n", f.FieldType)
				}
				start = start + f.Length
			}
			nfd.Records = append(nfd.Records, fr)
		} else {
			// This handles padding at the end of the flowset
			start = start + (nfd.Length - start) // Advance 'start' to the end of the flowset
		}
	}
	return nfd
}

/*
ParseTemplate

Slices a flow template out of an overall packet
Requires
	templateSlice []byte : Full packet bytes
Returns
	netFlowPacketTemplate: Struct of template
*/
func parseTemplate(templateSlice []byte) netflowPacketTemplate {
	template := netflowPacketTemplate{
		Fields: make([]templateField, 0),
	}
	template.ID = binary.BigEndian.Uint16(templateSlice[4:6])

	// Get the number of Fields
	template.FieldCount = binary.BigEndian.Uint16(templateSlice[6:8])
	// Start at the first fields and work through
	fieldStart := 8
	var read = uint16(0)
	for read < template.FieldCount {
		fieldTypeEnd := fieldStart + 2
		fieldType := binary.BigEndian.Uint16(templateSlice[fieldStart:fieldTypeEnd])
		fieldLengthEnd := fieldTypeEnd + 2
		fieldLength := binary.BigEndian.Uint16(templateSlice[fieldTypeEnd:fieldLengthEnd])

		// Create template FIELD struct
		field := templateField{
			FieldType: fieldType,
			Length:    fieldLength,
		}
		// Template fields are IN ORDER
		// Order determines records in data flowset
		template.Fields = append(template.Fields, field)

		read++
		fieldStart = fieldLengthEnd
		template.FieldLength = template.FieldLength + fieldLength
	}
	return template
}

/*
Route
Takes an entire packet slice, and routes each flowset to the correct handler

Requires
	nfp netflowPacket : netflowpacket struct
	p []byte        : Packet bytes
	start uint16        : Byte index to start at (skip the headers, etc)
	logger *log.Logger : Logger instance for warnings
*/
func Route(nfp netflowPacket, p []byte, start uint16, logger *log.Logger) netflowPacket {
	id := uint16(0)
	l := uint16(0)

	for int(start) < nfp.Length {
		// Check if there's enough bytes for ID and Length
		if int(start+4) > nfp.Length {
			logger.Printf("Warning: Malformed flowset header. Remaining packet length (%d) less than expected (4 bytes for ID+Length). Skipping remaining packet.\n", nfp.Length-int(start))
			break // Break out of the loop if header cannot be read
		}

		id = binary.BigEndian.Uint16(p[start : start+2])
		l = binary.BigEndian.Uint16(p[start+2 : start+4])

		// Check if the announced flowset length overruns the packet
		if int(start+l) > nfp.Length {
			logger.Printf("Warning: Flowset ID %d announced length %d, but only %d bytes remain in packet. Skipping this flowset.\n", id, l, nfp.Length-int(start))
			break // Break or advance by remaining length, depending on desired robustness
		}

		// Slice the next flowset out
		s := p[start : start+l]
		// Flowset ID is the switch we use to determine what sort of flowset follows
		switch {
		// Template flowset
		case id == uint16(0):
			t := parseTemplate(s)
			// If we've not had a template from this box yet
			if _, ok := nfp.Templates[nfp.Source]; !ok {
				nfp.Templates[nfp.Source] = make(map[uint32]map[uint16]netflowPacketTemplate)
			}

			if _, ok := nfp.Templates[nfp.Source][nfp.Header.Id]; !ok {
				nfp.Templates[nfp.Source][nfp.Header.Id] = make(map[uint16]netflowPacketTemplate)
			}
			nfp.Templates[nfp.Source][nfp.Header.Id][t.ID] = t

		// Data flowset
		case id > uint16(255):
			d := parseData(nfp, s, logger) // Pass logger to parseData
			nfp.Data = append(nfp.Data, d)
		default:
			// Handle unknown flowset IDs (e.g., options templates, other future types)
			logger.Printf("Warning: Unknown Flowset ID %d encountered. Skipping flowset.\n", id)
		}
		start = start + l
	}
	return nfp
}

func (n *Netflow) Configure(config map[string]string) {
	n.BindAddr = net.ParseIP(config["bindaddr"])
	test, err := strconv.Atoi(config["bindport"])
	n.BindPort = test
	if err != nil {
		panic(fmt.Sprintf("Error parsing bindport: %v", err)) // Use fmt.Sprintf for panic messages
	}

	// Check for the debug flag in the config
	if debugVal, ok := config["debug"]; ok {
		n.debug, err = strconv.ParseBool(debugVal)
		if err != nil {
			panic(fmt.Sprintf("Error parsing debug flag: %v", err))
		}
	}

	var logOutput io.Writer = os.Stdout // Default to stdout for debug=true or if file logging fails
	logFileName := "goflow.log"        // Default log file name

	// If not in debug mode, try to open a log file
	if !n.debug {
		file, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// If we can't open the log file, fall back to stdout and print an error
			fmt.Printf("Error opening log file %s: %v. Logging to stdout instead.\n", logFileName, err)
			logOutput = os.Stdout
		} else {
			logOutput = file
			n.logFile = file // Store the file handle to close it later
		}
	}

	// Initialize the logger
	n.logger = log.New(logOutput, "GOFLOW: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Initialize the channel for flowenricher
	n.FlowChannel = make(chan map[uint16]fields.Value, 1000) // Example buffer size
}

func (nf Netflow) Start() {
	// Close the log file when the Start method exits (e.g., on program shutdown)
	if nf.logFile != nil {
		defer func() {
			if err := nf.logFile.Close(); err != nil {
				// Use fmt.Printf here as the logger might be closed or have issues
				fmt.Printf("Error closing log file: %v\n", err)
			}
		}()
	}

	// If not in debug mode, ensure the channel is ready
	if !nf.debug {
		if nf.FlowChannel == nil {
			nf.logger.Printf("Error: FlowChannel is not initialized when debug is false. Exiting.\n")
			os.Exit(1) // Exit if channel is not ready in non-debug mode
		}
	}

	addr := net.UDPAddr{
		Port: nf.BindPort,
		IP:   nf.BindAddr,
	}
	conn, err := net.ListenUDP("udp", &addr)

	if err != nil {
		nf.logger.Printf("Error listening on UDP: %v\n", err)
		return
	}
	nf.logger.Printf("Listen on Addr: %v, Port: %v\n", nf.BindAddr, nf.BindPort)
	nf.Templates = make(map[uint32]map[uint32]map[uint16]netflowPacketTemplate)
	// Listen to incoming flows
	for {
		nfpacket := netflowPacket{
			Templates: nf.Templates,
		}

		p := netflowPacketHeader{}
		packet := make([]byte, 1500)
		var remoteAddr *net.UDPAddr
		nfpacket.Length, remoteAddr, err = conn.ReadFromUDP(packet)
		if err != nil {
			nf.logger.Printf("Error reading from UDP: %v\n", err)
			continue // Continue to next iteration on read error
		}

		nfpacket.Source = binary.BigEndian.Uint32(remoteAddr.IP)
		p.Version = binary.BigEndian.Uint16(packet[:2])
		// Ensure enough bytes for header fields before accessing
		if nfpacket.Length < 20 { // Minimum header length for v9
			nf.logger.Printf("Warning: Packet too short for Netflow v9 header. Length: %d. Skipping.\n", nfpacket.Length)
			continue
		}

		p.Uptime = binary.BigEndian.Uint32(packet[4:8])
		p.Usecs = binary.BigEndian.Uint32(packet[8:12])
		p.Sequence = binary.BigEndian.Uint32(packet[12:16])
		p.Id = binary.BigEndian.Uint32(packet[16:20])
		switch p.Version {
		case 5:
			nf.logger.Printf("Wrong Netflow version (%d), only v9+ supported. Exiting.\n", p.Version)
			os.Exit(1)
		case 9: // Explicitly handle v9
			// Continue processing
		default:
			nf.logger.Printf("Unsupported Netflow version (%d). Skipping packet.\n", p.Version)
			continue // Skip packet if version is not 9
		}

		nfpacket.Header = p
		nfpacket = Route(nfpacket, packet, uint16(20), nf.logger) // Pass logger to Route
		nf.Templates = nfpacket.Templates
		for _, dfs := range nfpacket.Data {
			for _, record := range dfs.Records {
				record.calcTime(p.Uptime, p.Usecs)
				// Conditional dispatch based on the debug flag
				if nf.debug {
					// Directly print to stdout via logger
					var sl []string
					for t, val := range record.ValuesMap {
						sl = append(sl, fmt.Sprintf("(%v)%v", t, val.ToString()))
					}
					nf.logger.Printf("%v\n", strings.Join(sl, " : "))
				} else {
					// Send the record to the Go channel for flowenricher
					select {
					case nf.FlowChannel <- record.ValuesMap:
						// Successfully sent
					default:
						// Channel is full, drop the flow or log a warning
						nf.logger.Printf("Warning: FlowChannel is full, dropping flow record.\n")
					}
				}
			}
		}
	}
}

