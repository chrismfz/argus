package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
	"github.com/yl2chen/cidranger"
	"flowenricher/enrich"
)

type InsertFlowBatcher struct {
	inserter      *ClickHouseInserter
	batchSize     int
	flushInterval time.Duration
	ranger        cidranger.Ranger
	buffer        []*FlowRecord
	lock          sync.Mutex
	ticker        *time.Ticker
	flushCtx      context.Context
	flushCancel   context.CancelFunc
	isFlushing    bool
	myASN  uint32
	myNets []*net.IPNet
	ifNames *enrich.IFNameCache
}


func NewInsertFlowBatcher(
    inserter *ClickHouseInserter,
    batchSize int,
    flushInterval time.Duration,
    ranger cidranger.Ranger,
    myASN uint32,
    myNets []*net.IPNet,
    ifNames *enrich.IFNameCache,
) *InsertFlowBatcher {
    ctx, cancel := context.WithCancel(context.Background())
    b := &InsertFlowBatcher{
        inserter:      inserter,
        batchSize:     batchSize,
        flushInterval: flushInterval,
        ranger:        ranger,
        buffer:        make([]*FlowRecord, 0, batchSize),
        ticker:        time.NewTicker(flushInterval),
        flushCtx:      ctx,
        flushCancel:   cancel,
        isFlushing:    false,
        myASN:         myASN,
        myNets:        myNets,
        ifNames:       ifNames, // ✅ ΤΩΡΑ σωστά
    }
    go b.autoFlushLoop()
    return b
}



func (b *InsertFlowBatcher) Add(flow *FlowRecord) {
	b.lock.Lock()
	b.buffer = append(b.buffer, flow)
	shouldFlush := len(b.buffer) >= b.batchSize && !b.isFlushing
	b.lock.Unlock()

	if shouldFlush {
		go b.flush()
	}
}

func (b *InsertFlowBatcher) autoFlushLoop() {
	for {
		select {
		case <-b.ticker.C:
			b.flush()
		case <-b.flushCtx.Done():
			return
		}
	}
}










func (b *InsertFlowBatcher) flush() {
    b.lock.Lock()
    if b.isFlushing {
        b.lock.Unlock()
        return
    }
    b.isFlushing = true
    batch := b.buffer
    b.buffer = make([]*FlowRecord, 0, b.batchSize)
    b.lock.Unlock()

    defer func() {
        b.lock.Lock()
        b.isFlushing = false
        b.lock.Unlock()
    }()

    if len(batch) == 0 {
        return
    }

    // ✅ enrich.GeoIP enrichment (ανεξάρτητα από BGP)
    for _, rec := range batch {
        if geo != nil {
            rec.SrcHostCountry = geo.GetCountry(rec.SrcHost)
            rec.DstHostCountry = geo.GetCountry(rec.DstHost)
            rec.PeerSrcASName = geo.GetASNName(rec.SrcHost)
            rec.PeerDstASName = geo.GetASNName(rec.DstHost)
        }
    }

// interface names
for _, rec := range batch {
    if rec.InputInterface != 0 && b.ifNames != nil {
        rec.InputInterfaceName = b.ifNames.Get(rec.InputInterface)
    }
    if rec.OutputInterface != 0 && b.ifNames != nil {
        rec.OutputInterfaceName = b.ifNames.Get(rec.OutputInterface)
    }
}


// ✅ BGP enrichment - για SrcHost
for _, rec := range batch {
    ip := net.ParseIP(rec.SrcHost)
    if ip == nil {
        continue
    }
    entries, err := b.ranger.ContainingNetworks(ip)
    if err != nil || len(entries) == 0 {
        continue
    }

    var bestEntry cidranger.RangerEntry
    bestMask := -1
    for _, entry := range entries {
        mask, _ := entry.Network().Mask.Size()
        if mask > bestMask {
            bestMask = mask
            bestEntry = entry
        }
    }

    enriched, ok := bestEntry.(BGPEnrichedEntry)
    if !ok {
        continue
    }

    if rec.ASPath == nil || len(rec.ASPath) == 0 {
        rec.ASPath = enriched.ASPath
    }
	rec.LocalPref = enriched.LocalPref
	rec.PeerSrcAS = enriched.ASN
}






// ✅ BGP enrichment - για DstHost
for _, rec := range batch {
    ip := net.ParseIP(rec.DstHost)
    if ip == nil {
        continue
    }

    entries, err := b.ranger.ContainingNetworks(ip)
    if err != nil || len(entries) == 0 {
        continue
    }

    var bestEntry cidranger.RangerEntry
    bestMask := -1
    for _, entry := range entries {
        mask, _ := entry.Network().Mask.Size()
        if mask > bestMask {
            bestMask = mask
            bestEntry = entry
        }
    }

    enriched, ok := bestEntry.(BGPEnrichedEntry)
    if !ok {
        continue
    }

    if rec.ASPath == nil || len(rec.ASPath) == 0 {
        rec.ASPath = enriched.ASPath
    }
    rec.LocalPref = enriched.LocalPref
        rec.DstAS = enriched.ASN
	rec.PeerDstAS = enriched.ASN
}






    dlog("Flushing %d flows to ClickHouse", len(batch))

    if err := b.inserter.InsertBatch(context.Background(), batch); err != nil {
        log.Printf("[ERROR] Failed to insert batch: %v", err)
    }
}






func (b *InsertFlowBatcher) Close() {
	b.flushCancel()
	b.ticker.Stop()
	b.flush()
}


