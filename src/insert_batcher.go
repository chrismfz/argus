package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
	"github.com/yl2chen/cidranger"
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
}



func (b *InsertFlowBatcher) isMine(ip net.IP) bool {
    for _, n := range b.myNets {
        // Normalize: Αν και τα δύο είναι IPv4 (wrapped σε 16 bytes), κάνε unwrap
        ipNormalized := ip
        netIPNormalized := n.IP

        if ip4 := ip.To4(); ip4 != nil {
            ipNormalized = ip4
        }
        if netIP4 := n.IP.To4(); netIP4 != nil {
            netIPNormalized = netIP4
        }

        normalizedNet := &net.IPNet{
            IP:   netIPNormalized,
            Mask: n.Mask,
        }

        if normalizedNet.Contains(ipNormalized) {
            log.Printf("[DEBUG] IP %s matched local prefix %s -> using MyASN %d", ipNormalized.String(), normalizedNet.String(), b.myASN)
            return true
        } else {
            log.Printf("[TRACE] IP %s not in %s", ipNormalized.String(), normalizedNet.String())
        }
    }
    return false
}



func NewInsertFlowBatcher(
    inserter *ClickHouseInserter,
    batchSize int,
    flushInterval time.Duration,
    ranger cidranger.Ranger,
    myASN uint32,
    myNets []*net.IPNet,
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

    // ✅ GeoIP enrichment (ανεξάρτητα από BGP)
    for _, rec := range batch {
        if geo != nil {
            rec.SrcHostCountry = geo.GetCountry(rec.SrcHost)
            rec.DstHostCountry = geo.GetCountry(rec.DstHost)
            rec.PeerSrcASName = geo.GetASNName(rec.SrcHost)
            rec.PeerDstASName = geo.GetASNName(rec.DstHost)
        }
    }





// ✅ BGP enrichment - για SrcHost
for _, rec := range batch {
    ip := net.ParseIP(rec.SrcHost)
    if ip == nil {
        continue
    }
dlog("[DEBUG] Enriching SrcHost: %s", ip.String())

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

    if b.isMine(ip) {
        rec.PeerSrcAS = b.myASN
        log.Printf("[MINE][SRC] %s belongs to my prefix -> setting ASN = %d", ip, b.myASN)
    } else {
        rec.PeerSrcAS = enriched.ASN
        log.Printf("[BGP][SRC] %s => ASN %d from prefix %s", ip, enriched.ASN, enriched.Net.String())
    }
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

    if b.isMine(ip) {
        rec.PeerDstAS = b.myASN
        rec.DstAS = b.myASN
        log.Printf("[MINE][DST] %s belongs to my prefix -> setting ASN = %d", ip, b.myASN)
    } else {
        rec.PeerDstAS = enriched.ASN
        rec.DstAS = enriched.ASN
        log.Printf("[BGP][DST] %s => ASN %d from prefix %s", ip, enriched.ASN, enriched.Net.String())
    }
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


