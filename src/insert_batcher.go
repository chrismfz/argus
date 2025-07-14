package main

import (
	"context"
	"fmt"
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
}

func NewInsertFlowBatcher(inserter *ClickHouseInserter, batchSize int, flushInterval time.Duration, ranger cidranger.Ranger) *InsertFlowBatcher {
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

	// BGP enrichment using ranger
	for _, rec := range batch {
		// check both src and dst
		for _, ipStr := range []string{rec.SrcHost, rec.DstHost} {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			entries, err := b.ranger.ContainingNetworks(ip)
			if err != nil || len(entries) == 0 {
				continue
			}

			// pick most specific (longest prefix)
			var bestEntry cidranger.RangerEntry
			bestMask := -1
			for _, entry := range entries {
				mask, _ := entry.Network().Mask.Size()
				if mask > bestMask {
					bestMask = mask
					bestEntry = entry
				}
			}
			if bestEntry == nil {
				continue
			}

enriched, ok := bestEntry.(BGPEnrichedEntry)
if !ok {
    continue
}
prefix := enriched.network.String()
path := enriched.ASPath
localPref := enriched.LocalPref
rec.LocalPref = localPref
			if rec.ASPath == nil || len(rec.ASPath) == 0 {
				rec.ASPath = path
			}

			asn, _ := toASNFromPrefix(prefix)
			if ipStr == rec.SrcHost {
				rec.PeerSrcAS = asn
				if geo != nil {
					rec.PeerSrcASName = geo.GetASNName(ipStr)
				}
			} else if ipStr == rec.DstHost {
				rec.PeerDstAS = asn
				if geo != nil {
					rec.PeerDstASName = geo.GetASNName(ipStr)
				}
				rec.DstAS = asn
			}
		}
	}

	dlog("Flushing %d flows to ClickHouse", len(batch))

	if err := b.inserter.InsertBatch(context.Background(), batch); err != nil {
		log.Printf("[ERROR] Failed to insert batch: %v", err)
	}
}

func toASNFromPrefix(prefix string) (uint32, error) {
	// For now we just extract the prefix and fake an ASN
	// In future you could map prefixes to ASNs via another map
	var asn uint32 = 0
	_, err := fmt.Sscanf(prefix, "%d", &asn)
	return asn, err
}

func (b *InsertFlowBatcher) Close() {
	b.flushCancel()
	b.ticker.Stop()
	b.flush()
}
