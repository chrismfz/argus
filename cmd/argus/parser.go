package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
        "argus/internal/enrich"
	"argus/internal/flow"

)

func ParseAndEnrich(line string, geo *enrich.GeoIP, dns *enrich.DNSResolver, timezone string) (*flow.FlowRecord, error) {
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




    // enrich.GeoIP / ASN
    var srcCountry, dstCountry, srcASNName, dstASNName string
    var srcASN, dstASN, dstAS uint32
    if geo != nil {
        srcCountry = geo.GetCountry(src)
        dstCountry = geo.GetCountry(dst)
        srcASN = geo.GetASNNumber(src)
        dstASN = geo.GetASNNumber(dst)
        dstAS = geo.GetASNNumber(dst)
        srcASNName = geo.GetASNName(src)
        dstASNName = geo.GetASNName(dst)
    }


    return &flow.FlowRecord{
        TimestampStart:   tUTC,
        Proto:            proto,
        TCPFlags:         toUint8(j["tcp_flags"]),
        TOS:              toUint8(j["tos"]),
        SrcHost:          src,
        SrcPort:          toUint16(j["port_src"]),
        SrcHostCountry:   srcCountry,
        DstHost:          dst,
        DstPort:          toUint16(j["port_dst"]),
        DstHostCountry:   dstCountry,
        PeerSrcAS:        toUint32(j["peer_as_src"], srcASN),
        PeerDstAS:        toUint32(j["peer_as_dst"], dstASN),
        Packets:          toUint64(j["packets"]),
        Bytes:            toUint64(j["bytes"]),
        PeerDstASName:    dstASNName,
        PeerSrcASName:    srcASNName,
        DstAS:            dstAS,
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
