package detection

import (
	"time"
)

type srcWindow struct {
	flows []Flow
}

func (w *srcWindow) prune(cut time.Time) {
	j := 0
	for _, x := range w.flows {
		if x.Timestamp.After(cut) {
			w.flows[j] = x
			j++
		}
	}
	w.flows = w.flows[:j]
}

func (w *srcWindow) add(f Flow, cut time.Time) {
	w.prune(cut)
	w.flows = append(w.flows, f)
}

// buildFeatures – uses your Flow fields (packets, bytes, proto/flags, dst ip/port)
func buildFeatures(flows []Flow, windowSec float64) featureVector {
	if windowSec <= 0 { windowSec = 1 }
	var pkts, bytes uint64
	uniDst := map[string]struct{}{}
	uniPorts := map[uint16]struct{}{}
	var tcpPkts, tcpSyn uint64
	var icmpPkts uint64

	for _, f := range flows {
		pkts += f.Packets
		bytes += f.Bytes
		uniDst[f.DstIP] = struct{}{}
		uniPorts[f.DstPort] = struct{}{}
		switch f.Proto {
		case "tcp":
			tcpPkts += f.Packets
			if f.TCPFlags&0x02 != 0 { // SYN
				tcpSyn += f.Packets
			}
		case "icmp":
			icmpPkts += f.Packets
		}
	}

	pktsPerSec := float64(pkts) / windowSec
	bytesPerSec := float64(bytes) / windowSec
	meanPkt := 0.0
	if pkts > 0 { meanPkt = float64(bytes) / float64(pkts) }
	tcpSynRatio := 0.0
	if tcpPkts > 0 { tcpSynRatio = float64(tcpSyn) / float64(tcpPkts) }
	icmpShare := 0.0
	if pkts > 0 { icmpShare = float64(icmpPkts) / float64(pkts) }

	return featureVector{
		PktsPerSec:   pktsPerSec,
		BytesPerSec:  bytesPerSec,
		MeanPktSize:  meanPkt,
		UniqDstIPs:   float64(len(uniDst)),
		UniqDstPorts: float64(len(uniPorts)),
		TCPSYNRatio:  tcpSynRatio,
		ICMPShare:    icmpShare,
	}
}
