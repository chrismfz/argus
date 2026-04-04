// Package flowstore accumulates per-ASN flow metrics in memory and
// periodically flushes them to SQLite. Two flush cadences:
//
//   - Every 5 minutes → flowstore_timeline     (bytes/packets/flows + iface split)
//   - Every 1 hour    → flowstore_top_ips,
//                       flowstore_top_prefixes,
//                       flowstore_proto,
//                       flowstore_country,
//                       flowstore_ports,
//                       flowstore_tcp_flags
//
// A permanent flowstore_asn_meta table tracks first/last seen and lifetime
// byte totals for every ASN encountered.
package flowstore

import (
	"database/sql"
	"log"
	"net"
	"sync"
	"time"

	"argus/internal/enrich"
	"github.com/yl2chen/cidranger"
)

// FlowEvent carries the fields flowstore needs from an enriched FlowRecord.
// Defined here (not in the flow package) to avoid an import cycle.
// batcher.go maps *flow.FlowRecord → flowstore.FlowEvent before calling Accumulate.
type FlowEvent struct {
	FlowDirection       uint8
	SrcHost             string
	DstHost             string
	PeerSrcAS           uint32
	PeerSrcASName       string
	PeerDstAS           uint32
	PeerDstASName       string
	InputInterface      uint32
	OutputInterface     uint32
	InputInterfaceName  string
	OutputInterfaceName string
	Proto               uint8
	TCPFlags            uint8
	SrcPort             uint16
	DstPort             uint16
	Bytes               uint64
	Packets             uint64
}

// Global is the package-level Store singleton, initialised by Init.
var Global *Store

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	topIPs    = 50    // top IP pairs kept per (hour, asn, dir) bucket
	topPfx    = 20    // top BGP prefixes kept per bucket
	topPorts  = 10    // top dst ports kept per bucket
	ipCap     = 10000 // max unique IP pairs tracked per hour bucket
	pfxCap    = 1000  // max unique prefixes tracked per hour bucket
	portCap   = 500   // max unique ports tracked per hour bucket
	retention = 7     // days to keep flowstore data
)

// ── Key types ─────────────────────────────────────────────────────────────────

type tlKey struct {
	ts  int64  // 5-min aligned unix epoch
	asn uint32
	dir string // "in" | "out"
}

type hourKey struct {
	ts  int64  // hour-aligned unix epoch
	asn uint32
	dir string // "in" | "out"
}

type ipKey struct {
	peerIP  string
	localIP string
	proto   uint8
	dstPort uint16
}

// ── Value / accumulator types ─────────────────────────────────────────────────

// counter is a generic bytes/packets/flows accumulator.
type counter struct {
	bytes   uint64
	packets uint64
	flows   uint64
}

func (c *counter) add(bytes, packets uint64) {
	c.bytes += bytes
	c.packets += packets
	c.flows++
}

// ipCounter extends counter with the peer IP's country (set once at insert).
type ipCounter struct {
	country string
	counter
}

// tlVal accumulates 5-min timeline data for one (asn, dir) slot.
type tlVal struct {
	asnName string
	counter
	ifaces map[string]uint64 // ifaceName → bytes
}

// hourAccum holds all hourly accumulators for one (asn, dir) bucket.
type hourAccum struct {
	asnName string
	ips     map[ipKey]*ipCounter   // top IPs
	pfx     map[string]*counter    // top BGP prefixes
	proto   map[uint8]*counter     // proto number → counter
	country map[string]*counter    // ISO country code → counter
	ports   map[uint16]*counter    // dst port → counter
	// TCP flag counters — TCP flows only
	tcpFlows                      uint64
	synCount, ackCount, rstCount  uint64
	finCount, pshCount, urgCount  uint64
}

// metaDelta carries the per-flush delta for flowstore_asn_meta.
type metaDelta struct {
	asnName   string
	firstSeen int64
	lastSeen  int64
	deltaIn   uint64 // bytes accumulated since last flush
	deltaOut  uint64
}

// metaAccum tracks running state for an ASN in memory (never reset).
type metaAccum struct {
	asnName   string
	firstSeen int64
	lastSeen  int64
	// running delta counters, reset to 0 after each flush
	pendingIn  uint64
	pendingOut uint64
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store is the central in-memory accumulator and SQLite writer.
type Store struct {
	mu sync.Mutex

	// 5-min timeline accumulators — flushed and reset every 5 min.
	tl map[tlKey]*tlVal

	// Hourly accumulators — flushed and reset every hour.
	hours map[hourKey]*hourAccum

	// Permanent ASN metadata — never reset, written as deltas on each 5-min flush.
	meta map[uint32]*metaAccum

	db             *sql.DB
	myASN          uint32
	myNets         []*net.IPNet
	upstreamIfaces map[uint32]bool
	ranger         cidranger.Ranger // for BGP prefix lookup on peer IPs
	geo            *enrich.GeoIP
}

// ── Initialisation ────────────────────────────────────────────────────────────

// Init creates the schema, warms up meta from DB, starts flush goroutines,
// and sets Global. Call once from main, after telemetry.Init.
func Init(
	db *sql.DB,
	myASN uint32,
	myNets []*net.IPNet,
	upstreamIfaces []uint32,
	ranger cidranger.Ranger,
	geo *enrich.GeoIP,
) error {
	if err := initSchema(db); err != nil {
		return err
	}

	ifSet := make(map[uint32]bool, len(upstreamIfaces))
	for _, idx := range upstreamIfaces {
		ifSet[idx] = true
	}

	s := &Store{
		tl:             make(map[tlKey]*tlVal),
		hours:          make(map[hourKey]*hourAccum),
		meta:           make(map[uint32]*metaAccum),
		db:             db,
		myASN:          myASN,
		myNets:         myNets,
		upstreamIfaces: ifSet,
		ranger:         ranger,
		geo:            geo,
	}

	if err := s.warmupMeta(); err != nil {
		log.Printf("[flowstore] meta warmup failed: %v", err)
	}

	Global = s
	go s.loop()
	return nil
}

// loop runs the three periodic tickers.
func (s *Store) loop() {
	tick5m  := time.NewTicker(5 * time.Minute)
	tick1h  := time.NewTicker(30 * time.Minute)
	tick24h := time.NewTicker(24 * time.Hour)
	defer tick5m.Stop()
	defer tick1h.Stop()
	defer tick24h.Stop()

	for {
		select {
		case <-tick5m.C:
			if err := s.flush5m(); err != nil {
				log.Printf("[flowstore] flush5m: %v", err)
			}
		case <-tick1h.C:
			if err := s.flushHourly(); err != nil {
				log.Printf("[flowstore] flushHourly: %v", err)
			}
		case <-tick24h.C:
			if err := s.prune(); err != nil {
				log.Printf("[flowstore] prune: %v", err)
			}
		}
	}
}

// ── Accumulate ────────────────────────────────────────────────────────────────

// Accumulate ingests one enriched flow event into the in-memory accumulators.
// Called from flow.FlowEnricher.enrichAndFeed via a FlowEvent mapping —
// must be fast and non-blocking.
func (s *Store) Accumulate(rec *FlowEvent) {
	inbound := s.classifyInbound(rec)

	// Resolve peer ASN, peer IP, local IP, and upstream interface name.
	var peerASN uint32
	var peerASNName, peerIP, localIP, ifaceName string
	var dir string

	if inbound {
		peerASN     = rec.PeerSrcAS
		peerASNName = rec.PeerSrcASName
		peerIP      = rec.SrcHost
		localIP     = rec.DstHost
		ifaceName   = rec.InputInterfaceName
		dir         = "in"
	} else {
		peerASN     = rec.PeerDstAS
		peerASNName = rec.PeerDstASName
		peerIP      = rec.DstHost
		localIP     = rec.SrcHost
		ifaceName   = rec.OutputInterfaceName
		dir         = "out"
	}

	// Skip unknown ASNs, our own ASN, and flows where the "peer" IP is ours.
	if peerASN == 0 || peerASN == s.myASN || s.isMyIP(peerIP) {
		return
	}

	now  := time.Now()
	ts5  := (now.Unix() / 300) * 300
	ts1h := (now.Unix() / 1800) * 1800

	s.mu.Lock()
	defer s.mu.Unlock()

	// ── meta ──────────────────────────────────────────────────────────────────
	m := s.meta[peerASN]
	if m == nil {
		m = &metaAccum{asnName: peerASNName, firstSeen: now.Unix()}
		s.meta[peerASN] = m
	}
	m.lastSeen = now.Unix()
	if peerASNName != "" && m.asnName == "" {
		m.asnName = peerASNName
	}
	if inbound {
		m.pendingIn += rec.Bytes
	} else {
		m.pendingOut += rec.Bytes
	}

	// ── 5-min timeline ────────────────────────────────────────────────────────
	tk := tlKey{ts5, peerASN, dir}
	tv := s.tl[tk]
	if tv == nil {
		tv = &tlVal{asnName: peerASNName}
		s.tl[tk] = tv
	}
	tv.bytes   += rec.Bytes
	tv.packets += rec.Packets
	tv.flows++
	if ifaceName != "" {
		if tv.ifaces == nil {
			tv.ifaces = make(map[string]uint64)
		}
		tv.ifaces[ifaceName] += rec.Bytes
	}

	// ── hourly accumulators ───────────────────────────────────────────────────
	hk := hourKey{ts1h, peerASN, dir}
	ha := s.hours[hk]
	if ha == nil {
		ha = &hourAccum{
			asnName: peerASNName,
			ips:     make(map[ipKey]*ipCounter),
			pfx:     make(map[string]*counter),
			proto:   make(map[uint8]*counter),
			country: make(map[string]*counter),
			ports:   make(map[uint16]*counter),
		}
		s.hours[hk] = ha
	}

	// Top IPs
	ik := ipKey{peerIP, localIP, rec.Proto, rec.DstPort}
	if iv := ha.ips[ik]; iv != nil {
		iv.add(rec.Bytes, rec.Packets)
	} else if len(ha.ips) < ipCap {
		ha.ips[ik] = &ipCounter{
			country: s.geoCountry(peerIP),
			counter: counter{rec.Bytes, rec.Packets, 1},
		}
	}

	// Top prefixes (BGP-derived, /24 fallback)
	if pfx := s.lookupPrefix(peerIP); pfx != "" {
		if pv := ha.pfx[pfx]; pv != nil {
			pv.add(rec.Bytes, rec.Packets)
		} else if len(ha.pfx) < pfxCap {
			ha.pfx[pfx] = &counter{rec.Bytes, rec.Packets, 1}
		}
	}

	// Protocol breakdown
	if pv := ha.proto[rec.Proto]; pv != nil {
		pv.add(rec.Bytes, rec.Packets)
	} else {
		ha.proto[rec.Proto] = &counter{rec.Bytes, rec.Packets, 1}
	}

	// Country breakdown
	if c := s.geoCountry(peerIP); c != "" {
		if cv := ha.country[c]; cv != nil {
			cv.add(rec.Bytes, rec.Packets)
		} else {
			ha.country[c] = &counter{rec.Bytes, rec.Packets, 1}
		}
	}

	// Top destination ports
	if rec.DstPort > 0 {
		if pv := ha.ports[rec.DstPort]; pv != nil {
			pv.add(rec.Bytes, rec.Packets)
		} else if len(ha.ports) < portCap {
			ha.ports[rec.DstPort] = &counter{rec.Bytes, rec.Packets, 1}
		}
	}

	// TCP flags (TCP only)
	if rec.Proto == 6 {
		ha.tcpFlows++
		f := rec.TCPFlags
		if f&0x02 != 0 { ha.synCount++ }
		if f&0x10 != 0 { ha.ackCount++ }
		if f&0x04 != 0 { ha.rstCount++ }
		if f&0x01 != 0 { ha.finCount++ }
		if f&0x08 != 0 { ha.pshCount++ }
		if f&0x20 != 0 { ha.urgCount++ }
	}
}

// ── Direction classification ──────────────────────────────────────────────────

// classifyInbound mirrors telemetry.Aggregator.classifyDirection:
// upstream interface indices first, then IP prefix matching, then
// NetFlow DIRECTION field as last resort.
func (s *Store) classifyInbound(rec *FlowEvent) bool {
	// 1. Interface index — most reliable signal.
	if len(s.upstreamIfaces) > 0 {
		if rec.InputInterface != 0 && s.upstreamIfaces[rec.InputInterface] {
			return true
		}
		if rec.OutputInterface != 0 && s.upstreamIfaces[rec.OutputInterface] {
			return false
		}
	}
	// 2. IP prefix matching.
	if len(s.myNets) > 0 {
		if ip := net.ParseIP(rec.DstHost); ip != nil {
			for _, n := range s.myNets {
				if n.Contains(ip) {
					return true
				}
			}
		}
		if ip := net.ParseIP(rec.SrcHost); ip != nil {
			for _, n := range s.myNets {
				if n.Contains(ip) {
					return false
				}
			}
		}
	}
	// 3. NetFlow DIRECTION field fallback.
	return rec.FlowDirection == 0
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *Store) isMyIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range s.myNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// lookupPrefix returns the most-specific BGP prefix containing ipStr,
// falling back to a /24 approximation when the ranger has no entry.
func (s *Store) lookupPrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if s.ranger != nil {
		entries, err := s.ranger.ContainingNetworks(ip)
		if err == nil && len(entries) > 0 {
			best := entries[0]
			bestLen, _ := best.Network().Mask.Size()
			for _, e := range entries[1:] {
				if l, _ := e.Network().Mask.Size(); l > bestLen {
					bestLen = l
					best = e
				}
			}
			n := best.Network()
			return n.String()
		}
	}
	// Fallback: /24 approximation (IPv4 only).
	if ip4 := ip.To4(); ip4 != nil {
		return net.IP{ip4[0], ip4[1], ip4[2], 0}.String() + "/24"
	}
	return ""
}

func (s *Store) geoCountry(ipStr string) string {
	if s.geo == nil {
		return ""
	}
	return s.geo.GetCountry(ipStr)
}
