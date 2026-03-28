package telemetry

import (
	"net"
	"sort"
	"sync"
	"time"
)

const RingSize = 1440

var Global *Aggregator

// Record is a telemetry-local view of an enriched flow.
type Record struct {
	SrcHost             string
	DstHost             string
	PeerSrcAS           uint32
	PeerDstAS           uint32
	PeerSrcASName       string
	PeerDstASName       string
	Bytes               uint64
	Packets             uint64
	FlowDirection       uint8
	DstPort             uint16
	InputInterface      uint32
	OutputInterface     uint32
	InputInterfaceName  string
	OutputInterfaceName string
}

// ── public types ──────────────────────────────────────────────────────────────

type MinuteBucket struct {
	Ts       int64  `json:"ts"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	FlowsIn  uint64 `json:"flows_in"`
	FlowsOut uint64 `json:"flows_out"`
	PktsIn   uint64 `json:"pkts_in"`
	PktsOut  uint64 `json:"pkts_out"`
}

type ASNStat struct {
	ASN      uint32 `json:"asn"`
	Name     string `json:"name"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	FlowsIn  uint64 `json:"flows_in"`
	FlowsOut uint64 `json:"flows_out"`
}

type PairStat struct {
	SrcASN  uint32 `json:"src_asn"`
	SrcName string `json:"src_name"`
	DstASN  uint32 `json:"dst_asn"`
	DstName string `json:"dst_name"`
	Bytes   uint64 `json:"bytes"`
	Flows   uint64 `json:"flows"`
}

type HostStat struct {
	IP       string `json:"ip"`
	BytesIn  uint64 `json:"bytes_in,omitempty"`
	BytesOut uint64 `json:"bytes_out,omitempty"`
}

type PortStat struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

// IfaceMinBucket is one minute of traffic on one interface.
type IfaceMinBucket struct {
	Ts       int64  `json:"ts"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	FlowsIn  uint64 `json:"flows_in"`
	FlowsOut uint64 `json:"flows_out"`
}

// IfaceSeries is the time-series + totals for one interface.
type IfaceSeries struct {
	Index    uint32           `json:"index"`
	Name     string           `json:"name"`
	Series   []IfaceMinBucket `json:"series"`
	TotalIn  uint64           `json:"total_in"`
	TotalOut uint64           `json:"total_out"`
	FlowsIn  uint64           `json:"flows_in"`
	FlowsOut uint64           `json:"flows_out"`
}

// ── internal types ────────────────────────────────────────────────────────────

type asnMinCount struct {
	name     string
	bytesIn  uint64
	bytesOut uint64
	flowsIn  uint64
	flowsOut uint64
}

type ifaceMinCount struct {
	name     string
	bytesIn  uint64
	bytesOut uint64
	flowsIn  uint64
	flowsOut uint64
}

type pairKey struct{ SrcASN, DstASN uint32 }

type pairAccum struct {
	srcName, dstName string
	bytes, flows     uint64
}

// ── Aggregator ────────────────────────────────────────────────────────────────

type Aggregator struct {
	mu     sync.RWMutex
	myASN  uint32
	myName string
	myNets []*net.IPNet

	upstreamIfaces map[uint32]bool

	ring     [RingSize]MinuteBucket
	asnRing  [RingSize]map[uint32]*asnMinCount
	ifaceRing [RingSize]map[uint32]*ifaceMinCount // per-interface per-minute

	pairsIn  map[pairKey]*pairAccum
	pairsOut map[pairKey]*pairAccum
	hostsIn  map[string]uint64
	hostsOut map[string]uint64
	ports    map[uint16]uint64

	lastReset time.Time
}

func Init(myASN uint32, myName string, myNets []*net.IPNet, upstreamIfaces []uint32) {
	ifSet := make(map[uint32]bool, len(upstreamIfaces))
	for _, idx := range upstreamIfaces {
		ifSet[idx] = true
	}
	a := &Aggregator{
		myASN:          myASN,
		myName:         myName,
		myNets:         myNets,
		upstreamIfaces: ifSet,
		pairsIn:        make(map[pairKey]*pairAccum),
		pairsOut:       make(map[pairKey]*pairAccum),
		hostsIn:        make(map[string]uint64),
		hostsOut:       make(map[string]uint64),
		ports:          make(map[uint16]uint64),
		lastReset:      time.Now(),
	}
	for i := range a.asnRing {
		a.asnRing[i] = make(map[uint32]*asnMinCount)
	}
	for i := range a.ifaceRing {
		a.ifaceRing[i] = make(map[uint32]*ifaceMinCount)
	}
	Global = a
}

// ── helpers ───────────────────────────────────────────────────────────────────

func slotFor(t time.Time) int {
	return int((t.Unix() / 60) % RingSize)
}

func minEpoch(t time.Time) int64 {
	return (t.Unix() / 60) * 60
}

func (a *Aggregator) classifyDirection(rec *Record) (inbound, srcInMy, dstInMy bool) {
	// 1. Interface index (most reliable)
	if len(a.upstreamIfaces) > 0 {
		if rec.InputInterface != 0 && a.upstreamIfaces[rec.InputInterface] {
			return true, false, false
		}
		if rec.OutputInterface != 0 && a.upstreamIfaces[rec.OutputInterface] {
			return false, false, false
		}
	}
	// 2. IP prefix matching
	if len(a.myNets) > 0 {
		if ip := net.ParseIP(rec.DstHost); ip != nil {
			for _, n := range a.myNets {
				if n.Contains(ip) {
					dstInMy = true
					break
				}
			}
		}
		if ip := net.ParseIP(rec.SrcHost); ip != nil {
			for _, n := range a.myNets {
				if n.Contains(ip) {
					srcInMy = true
					break
				}
			}
		}
		if dstInMy {
			return true, srcInMy, dstInMy
		}
		if srcInMy {
			return false, srcInMy, dstInMy
		}
	}
	// 3. FlowDirection fallback
	return rec.FlowDirection == 0, srcInMy, dstInMy
}

// ── Ingest ────────────────────────────────────────────────────────────────────

func (a *Aggregator) Ingest(rec *Record) {
	now := time.Now()
	slot := slotFor(now)
	ts := minEpoch(now)

	inbound, srcInMy, dstInMy := a.classifyDirection(rec)
	Tap.ingest(rec, inbound, srcInMy, dstInMy)

	a.mu.Lock()
	defer a.mu.Unlock()

	// ── time-series ring ──────────────────────────────────────────────────
	b := &a.ring[slot]
	if b.Ts != ts {
		*b = MinuteBucket{Ts: ts}
		a.asnRing[slot] = make(map[uint32]*asnMinCount)
		a.ifaceRing[slot] = make(map[uint32]*ifaceMinCount)
	}
	if inbound {
		b.BytesIn += rec.Bytes
		b.FlowsIn++
		b.PktsIn += rec.Packets
	} else {
		b.BytesOut += rec.Bytes
		b.FlowsOut++
		b.PktsOut += rec.Packets
	}

	// ── ASN ring ──────────────────────────────────────────────────────────
	asn, asnName := rec.PeerSrcAS, rec.PeerSrcASName
	if !inbound {
		asn, asnName = rec.PeerDstAS, rec.PeerDstASName
	}
	if asn != 0 && asn != a.myASN {
		am := a.asnRing[slot]
		c, ok := am[asn]
		if !ok {
			c = &asnMinCount{name: asnName}
			am[asn] = c
		} else if c.name == "" && asnName != "" {
			c.name = asnName
		}
		if inbound {
			c.bytesIn += rec.Bytes
			c.flowsIn++
		} else {
			c.bytesOut += rec.Bytes
			c.flowsOut++
		}
	}

	// ── Interface ring ────────────────────────────────────────────────────
	// Track the "interesting" interface: for inbound = input (where it came from),
	// for outbound = output (where it went to). Both are upstream-facing.
	ifIdx := rec.InputInterface
	ifName := rec.InputInterfaceName
	if !inbound {
		ifIdx = rec.OutputInterface
		ifName = rec.OutputInterfaceName
	}
	if ifIdx != 0 {
		im := a.ifaceRing[slot]
		ic, ok := im[ifIdx]
		if !ok {
			ic = &ifaceMinCount{name: ifName}
			im[ifIdx] = ic
		} else if ic.name == "" && ifName != "" {
			ic.name = ifName
		}
		if inbound {
			ic.bytesIn += rec.Bytes
			ic.flowsIn++
		} else {
			ic.bytesOut += rec.Bytes
			ic.flowsOut++
		}
	}

	// ── Sankey pairs ──────────────────────────────────────────────────────
	srcASN, dstASN := rec.PeerSrcAS, rec.PeerDstAS
	srcName, dstName := rec.PeerSrcASName, rec.PeerDstASName
	if inbound && srcASN != 0 && srcASN != a.myASN {
		k := pairKey{srcASN, a.myASN}
		p, ok := a.pairsIn[k]
		if !ok {
			p = &pairAccum{srcName: srcName, dstName: a.myName}
			a.pairsIn[k] = p
		}
		p.bytes += rec.Bytes
		p.flows++
	}
	if !inbound && dstASN != 0 && dstASN != a.myASN {
		k := pairKey{a.myASN, dstASN}
		p, ok := a.pairsOut[k]
		if !ok {
			p = &pairAccum{srcName: a.myName, dstName: dstName}
			a.pairsOut[k] = p
		}
		p.bytes += rec.Bytes
		p.flows++
	}

	// ── Top hosts ─────────────────────────────────────────────────────────
	if inbound {
		if len(a.hostsIn) < 50000 {
			a.hostsIn[rec.DstHost] += rec.Bytes
		}
	} else {
		if len(a.hostsOut) < 50000 {
			a.hostsOut[rec.SrcHost] += rec.Bytes
		}
	}

	// ── Port heatmap ──────────────────────────────────────────────────────
	if rec.DstPort != 0 {
		a.ports[rec.DstPort]++
	}
}

// ── ResetAccumulators ─────────────────────────────────────────────────────────

func (a *Aggregator) ResetAccumulators() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pairsIn = make(map[pairKey]*pairAccum)
	a.pairsOut = make(map[pairKey]*pairAccum)
	a.hostsIn = make(map[string]uint64)
	a.hostsOut = make(map[string]uint64)
	a.ports = make(map[uint16]uint64)
	a.lastReset = time.Now()
}

// ── Query methods ─────────────────────────────────────────────────────────────

func (a *Aggregator) QueryTimeSeries(minutes int) []MinuteBucket {
	if minutes > RingSize {
		minutes = RingSize
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	cutoff := minEpoch(time.Now()) - int64(minutes-1)*60
	result := make([]MinuteBucket, 0, minutes)
	for i := 0; i < RingSize; i++ {
		if a.ring[i].Ts >= cutoff {
			result = append(result, a.ring[i])
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Ts < result[j].Ts })
	return result
}

func (a *Aggregator) QueryTopASN(n, minutes int) (topIn, topOut []ASNStat) {
	if minutes > RingSize {
		minutes = RingSize
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	cutoff := minEpoch(time.Now()) - int64(minutes)*60
	merged := make(map[uint32]*ASNStat, 256)
	for slot := 0; slot < RingSize; slot++ {
		if a.ring[slot].Ts < cutoff {
			continue
		}
		for asn, c := range a.asnRing[slot] {
			s, ok := merged[asn]
			if !ok {
				s = &ASNStat{ASN: asn, Name: c.name}
				merged[asn] = s
			}
			s.BytesIn += c.bytesIn
			s.BytesOut += c.bytesOut
			s.FlowsIn += c.flowsIn
			s.FlowsOut += c.flowsOut
			if s.Name == "" && c.name != "" {
				s.Name = c.name
			}
		}
	}
	all := make([]ASNStat, 0, len(merged))
	for _, s := range merged {
		all = append(all, *s)
	}
	in := make([]ASNStat, len(all))
	copy(in, all)
	sort.Slice(in, func(i, j int) bool { return in[i].BytesIn > in[j].BytesIn })
	if len(in) > n {
		in = in[:n]
	}
	out := make([]ASNStat, len(all))
	copy(out, all)
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	if len(out) > n {
		out = out[:n]
	}
	return in, out
}

// QueryInterfaces returns per-interface time-series for the last `minutes` minutes.
// Only interfaces that have seen traffic are returned.
func (a *Aggregator) QueryInterfaces(minutes int) []IfaceSeries {
	if minutes > RingSize {
		minutes = RingSize
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	cutoff := minEpoch(time.Now()) - int64(minutes-1)*60

	// collect all slots into per-interface series map
	// seriesMap[ifIdx][ts] = bucket
	type bucketKey struct {
		idx uint32
		ts  int64
	}
	buckets := make(map[bucketKey]*IfaceMinBucket)
	names := make(map[uint32]string)
	totals := make(map[uint32]*IfaceSeries)

	for slot := 0; slot < RingSize; slot++ {
		slotTs := a.ring[slot].Ts
		if slotTs < cutoff || slotTs == 0 {
			continue
		}
		for idx, ic := range a.ifaceRing[slot] {
			k := bucketKey{idx, slotTs}
			if _, ok := buckets[k]; !ok {
				buckets[k] = &IfaceMinBucket{Ts: slotTs}
			}
			bkt := buckets[k]
			bkt.BytesIn += ic.bytesIn
			bkt.BytesOut += ic.bytesOut
			bkt.FlowsIn += ic.flowsIn
			bkt.FlowsOut += ic.flowsOut
			if names[idx] == "" && ic.name != "" {
				names[idx] = ic.name
			}
			if totals[idx] == nil {
				totals[idx] = &IfaceSeries{Index: idx}
			}
			totals[idx].TotalIn += ic.bytesIn
			totals[idx].TotalOut += ic.bytesOut
			totals[idx].FlowsIn += ic.flowsIn
			totals[idx].FlowsOut += ic.flowsOut
		}
	}

	// build IfaceSeries per interface
	result := make([]IfaceSeries, 0, len(totals))
	for idx, tot := range totals {
		// collect and sort time buckets for this interface
		series := make([]IfaceMinBucket, 0, minutes)
		for k, bkt := range buckets {
			if k.idx == idx {
				series = append(series, *bkt)
			}
		}
		sort.Slice(series, func(i, j int) bool { return series[i].Ts < series[j].Ts })

		result = append(result, IfaceSeries{
			Index:    idx,
			Name:     names[idx],
			Series:   series,
			TotalIn:  tot.TotalIn,
			TotalOut: tot.TotalOut,
			FlowsIn:  tot.FlowsIn,
			FlowsOut: tot.FlowsOut,
		})
	}

	// sort by total traffic descending
	sort.Slice(result, func(i, j int) bool {
		return (result[i].TotalIn + result[i].TotalOut) > (result[j].TotalIn + result[j].TotalOut)
	})
	return result
}

func (a *Aggregator) QuerySankey(limit int) (sankeyIn, sankeyOut []PairStat) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	in := make([]PairStat, 0, len(a.pairsIn))
	for k, v := range a.pairsIn {
		in = append(in, PairStat{k.SrcASN, v.srcName, k.DstASN, v.dstName, v.bytes, v.flows})
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Bytes > in[j].Bytes })
	if len(in) > limit {
		in = in[:limit]
	}
	out := make([]PairStat, 0, len(a.pairsOut))
	for k, v := range a.pairsOut {
		out = append(out, PairStat{k.SrcASN, v.srcName, k.DstASN, v.dstName, v.bytes, v.flows})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return in, out
}

func (a *Aggregator) QueryTopHosts(n int) (topIn, topOut []HostStat) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	in := make([]HostStat, 0, len(a.hostsIn))
	for ip, b := range a.hostsIn {
		in = append(in, HostStat{IP: ip, BytesIn: b})
	}
	sort.Slice(in, func(i, j int) bool { return in[i].BytesIn > in[j].BytesIn })
	if len(in) > n {
		in = in[:n]
	}
	out := make([]HostStat, 0, len(a.hostsOut))
	for ip, b := range a.hostsOut {
		out = append(out, HostStat{IP: ip, BytesOut: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	if len(out) > n {
		out = out[:n]
	}
	return in, out
}

func (a *Aggregator) QueryPorts(n int) []PortStat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	list := make([]PortStat, 0, len(a.ports))
	for port, count := range a.ports {
		list = append(list, PortStat{Port: port, Count: count})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

type SnapshotData struct {
	TopASNIn    []ASNStat      `json:"asn_in"`
	TopASNOut   []ASNStat      `json:"asn_out"`
	TimeSeries  []MinuteBucket `json:"timeseries"`
	SankeyIn    []PairStat     `json:"sankey_in"`
	SankeyOut   []PairStat     `json:"sankey_out"`
	TopHostsIn  []HostStat     `json:"hosts_in"`
	TopHostsOut []HostStat     `json:"hosts_out"`
	TopPorts    []PortStat     `json:"ports"`
	Interfaces  []IfaceSeries  `json:"interfaces"`
}

func (a *Aggregator) BuildSnapshot(minutes int) SnapshotData {
	topIn, topOut := a.QueryTopASN(100, minutes)
	sankeyIn, sankeyOut := a.QuerySankey(100)
	hostsIn, hostsOut := a.QueryTopHosts(100)
	ports := a.QueryPorts(100)
	ts := a.QueryTimeSeries(minutes)
	ifaces := a.QueryInterfaces(minutes)
	return SnapshotData{
		TopASNIn:    topIn,
		TopASNOut:   topOut,
		TimeSeries:  ts,
		SankeyIn:    sankeyIn,
		SankeyOut:   sankeyOut,
		TopHostsIn:  hostsIn,
		TopHostsOut: hostsOut,
		TopPorts:    ports,
		Interfaces:  ifaces,
	}
}
