package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

func ParseAndEnrich(line string, geo *GeoIP, bgp *BGPTable, dns *DNSResolver, timezone string) (*FlowRecord, error) {
	var j map[string]interface{}
	err := json.Unmarshal([]byte(line), &j)
	if err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}

	if j["event_type"] != "purge" {
		return nil, fmt.Errorf("not a purge event")
	}

	// Parse timestamp_start
	tsStr, ok := j["timestamp_start"].(string)
	if !ok {
		return nil, fmt.Errorf("missing timestamp_start")
	}
	localTZ, _ := time.LoadLocation(timezone)
	t0, err := time.ParseInLocation("2006-01-02 15:04:05.000000", tsStr, localTZ)
	if err != nil {
		return nil, fmt.Errorf("timestamp parse error: %w", err)
	}
	tUTC := t0.UTC()

	// Protocol mapping
	proto := uint8(0)
	if ipProto, ok := j["ip_proto"].(string); ok {
		switch ipProto {
		case "icmp":
			proto = 1
		case "tcp":
			proto = 6
		case "udp":
			proto = 17
		}
	}

	// IPs
	src := j["ip_src"].(string)
	dst := j["ip_dst"].(string)

	// BGP AS Path
	var asPath []string
	if raw, ok := j["as_path"]; ok {
		if rawList, ok := raw.([]interface{}); ok {
			for _, el := range rawList {
				asPath = append(asPath, fmt.Sprintf("%v", el))
			}
		}
	}
	if len(asPath) == 0 {
		asPath = bgp.FindASPath(src)
		if len(asPath) == 0 {
			asPath = bgp.FindASPath(dst)
		}
	}

	// Ports
	srcPort := toUint16(j["port_src"])
	dstPort := toUint16(j["port_dst"])

	// Final struct
	return &FlowRecord{
		TimestampStart:   tUTC,
		Proto:            proto,
		TCPFlags:         toUint8(j["tcp_flags"]),
		TOS:              toUint8(j["tos"]),
		SrcHost:          src,
		SrcPort:          srcPort,
		SrcHostCountry:   geo.GetCountry(src),
		DstHost:          dst,
		DstPort:          dstPort,
		DstHostCountry:   geo.GetCountry(dst),
		PeerSrcAS:        toUint32(j["peer_as_src"], geo.GetASNNumber(src)),
		PeerDstAS:        toUint32(j["peer_as_dst"], geo.GetASNNumber(dst)),
		ASPath:           asPath,
		Packets:          toUint64(j["packets"]),
		Bytes:            toUint64(j["bytes"]),
		PeerDstASName:    geo.GetASNName(dst),
		PeerSrcASName:    geo.GetASNName(src),
		DstAS:            geo.GetASNNumber(dst),
		SrcHostPTR:       dns.LookupPTR(src),
		DstHostPTR:       dns.LookupPTR(dst),
	}, nil
}

func toUint8(v interface{}) uint8 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return uint8(x)
	case string:
		n, _ := strconv.Atoi(x)
		return uint8(n)
	default:
		return 0
	}
}

func toUint16(v interface{}) uint16 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return uint16(x)
	case string:
		n, _ := strconv.Atoi(x)
		return uint16(n)
	default:
		return 0
	}
}

func toUint32(v interface{}, fallback uint32) uint32 {
	if v == nil {
		return fallback
	}
	switch x := v.(type) {
	case float64:
		if x == 0 {
			return fallback
		}
		return uint32(x)
	case string:
		n, _ := strconv.Atoi(x)
		if n == 0 {
			return fallback
		}
		return uint32(n)
	default:
		return fallback
	}
}

func toUint64(v interface{}) uint64 {
	if v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return uint64(x)
	case string:
		n, _ := strconv.ParseUint(x, 10, 64)
		return n
	default:
		return 0
	}
}
