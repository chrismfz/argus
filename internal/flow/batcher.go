package flow

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"argus/internal/bgp"
	"argus/internal/clickhouse"
	"argus/internal/enrich"
	"github.com/yl2chen/cidranger"
	"argus/internal/telemetry"
)

// InsertFlowBatcher buffers FlowRecords, enriches them, and inserts into ClickHouse.
type InsertFlowBatcher struct {
	inserter    *clickhouse.Inserter
	batchSize   int
	flushEvery  time.Duration
	ranger      cidranger.Ranger
	geo         *enrich.GeoIP
	ifNames     *enrich.IFNameCache
	storeASPath bool

	mu       sync.Mutex
	buffer   []*FlowRecord
	flushing bool

	ticker *time.Ticker
	done   chan struct{}
}

func NewInsertFlowBatcher(
	inserter *clickhouse.Inserter,
	batchSize int,
	flushEvery time.Duration,
	ranger cidranger.Ranger,
	ifNames *enrich.IFNameCache,
	storeASPath bool,
	geo *enrich.GeoIP,
) *InsertFlowBatcher {
	b := &InsertFlowBatcher{
		inserter:    inserter,
		batchSize:   batchSize,
		flushEvery:  flushEvery,
		ranger:      ranger,
		geo:         geo,
		ifNames:     ifNames,
		storeASPath: storeASPath,
		buffer:      make([]*FlowRecord, 0, batchSize),
		ticker:      time.NewTicker(flushEvery),
		done:        make(chan struct{}),
	}
	go b.loop()
	return b
}

// Add enqueues a flow. If the buffer is full, flush is triggered.
func (b *InsertFlowBatcher) Add(rec *FlowRecord) {
	b.mu.Lock()
	b.buffer = append(b.buffer, rec)
	full := len(b.buffer) >= b.batchSize
	b.mu.Unlock()

	if full {
		b.triggerFlush()
	}
}

func (b *InsertFlowBatcher) loop() {
	for {
		select {
		case <-b.ticker.C:
			b.triggerFlush()
		case <-b.done:
			return
		}
	}
}

func (b *InsertFlowBatcher) triggerFlush() {
	b.mu.Lock()
	if b.flushing || len(b.buffer) == 0 {
		b.mu.Unlock()
		return
	}
	b.flushing = true
	batch := b.buffer
	b.buffer = make([]*FlowRecord, 0, b.batchSize)
	b.mu.Unlock()

	go func() {
		b.enrichAndFlush(batch)
		b.mu.Lock()
		b.flushing = false
		b.mu.Unlock()
	}()
}

// enrichAndFlush enriches all records in a single pass then inserts.
func (b *InsertFlowBatcher) enrichAndFlush(batch []*FlowRecord) {
	for _, rec := range batch {
		// ── Single pass: GeoIP + interface name + BGP ──────────────────
		if b.geo != nil {
			rec.SrcHostCountry = b.geo.GetCountry(rec.SrcHost)
			rec.DstHostCountry = b.geo.GetCountry(rec.DstHost)
			rec.PeerSrcASName  = b.geo.GetASNName(rec.SrcHost)
			rec.PeerDstASName  = b.geo.GetASNName(rec.DstHost)
		}

		if b.ifNames != nil {
			if rec.InputInterface != 0 {
				rec.InputInterfaceName = b.ifNames.Get(rec.InputInterface)
			}
			if rec.OutputInterface != 0 {
				rec.OutputInterfaceName = b.ifNames.Get(rec.OutputInterface)
			}
		}

		if b.ranger != nil {
			b.enrichBGP(rec)
		}
	}




    // ── Telemetry tap (Phase 1: runs alongside ClickHouse insert) ──────────
if telemetry.Global != nil {
    for _, rec := range batch {
        telemetry.Global.Ingest(&telemetry.Record{
            SrcHost:       rec.SrcHost,
            DstHost:       rec.DstHost,
            PeerSrcAS:     rec.PeerSrcAS,
            PeerDstAS:     rec.PeerDstAS,
            PeerSrcASName: rec.PeerSrcASName,
            PeerDstASName: rec.PeerDstASName,
            Bytes:         rec.Bytes,
            Packets:       rec.Packets,
            FlowDirection: rec.FlowDirection,
            DstPort:       rec.DstPort,
            InputInterface:  rec.InputInterface,   // ← add
            OutputInterface: rec.OutputInterface,  // ← add
        })
    }
}




	if err := b.insertBatch(context.Background(), batch); err != nil {
		log.Printf("[BATCHER] insert failed: %v", err)
	}
}

// enrichBGP fills BGP-derived fields from the cidranger.
func (b *InsertFlowBatcher) enrichBGP(rec *FlowRecord) {
	if dst := net.ParseIP(rec.DstHost); dst != nil {
		if entry, ok := b.bestMatch(dst); ok {
			if b.storeASPath && len(rec.ASPath) == 0 {
				rec.ASPath = entry.ASPath
			}
			if rec.LocalPref == 0 {
				rec.LocalPref = entry.LocalPref
			}
			if rec.DstAS == 0 {
				rec.DstAS = entry.ASN
			}
			if rec.PeerDstAS == 0 {
				rec.PeerDstAS = entry.ASN
			}
		}
	}

	if src := net.ParseIP(rec.SrcHost); src != nil {
		if entry, ok := b.bestMatch(src); ok && rec.PeerSrcAS == 0 {
			rec.PeerSrcAS = entry.ASN
		}
	}
}

func (b *InsertFlowBatcher) bestMatch(ip net.IP) (bgp.BGPEnrichedEntry, bool) {
	entries, err := b.ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return bgp.BGPEnrichedEntry{}, false
	}
	best := entries[0]
	bestLen, _ := best.Network().Mask.Size()
	for _, e := range entries[1:] {
		if l, _ := e.Network().Mask.Size(); l > bestLen {
			bestLen = l
			best = e
		}
	}
	entry, ok := best.(bgp.BGPEnrichedEntry)
	return entry, ok
}

func (b *InsertFlowBatcher) insertBatch(ctx context.Context, flows []*FlowRecord) error {
	chBatch, err := clickhouse.Global.PrepareBatch(ctx, b.inserter.Query())
	if err != nil {
		return err
	}
	for _, f := range flows {
		if err := chBatch.AppendStruct(f); err != nil {
			return err
		}
	}
	return chBatch.Send()
}

// Close flushes remaining records and stops the background loop.
func (b *InsertFlowBatcher) Close() {
	b.ticker.Stop()
	close(b.done)
	b.triggerFlush()
	// wait for in-flight flush
	time.Sleep(500 * time.Millisecond)
}
