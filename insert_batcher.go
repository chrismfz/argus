package main

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"
)

type InsertFlowBatcher struct {
    inserter       *ClickHouseInserter
    batchSize      int
    flushInterval  time.Duration
    buffer         []*FlowRecord
    lock           sync.Mutex
    ticker         *time.Ticker
    flushCtx       context.Context
    flushCancel    context.CancelFunc
    bgp            *BGPTable
    isFlushing     bool
}

func NewInsertFlowBatcher(inserter *ClickHouseInserter, batchSize int, flushInterval time.Duration, bgp *BGPTable) *InsertFlowBatcher {
    ctx, cancel := context.WithCancel(context.Background())
    b := &InsertFlowBatcher{
        inserter:      inserter,
        batchSize:     batchSize,
        flushInterval: flushInterval,
        buffer:        make([]*FlowRecord, 0, batchSize),
        ticker:        time.NewTicker(flushInterval),
        flushCtx:      ctx,
        flushCancel:   cancel,
        bgp:           bgp,
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

    // BGP Enrichment
    if b.bgp != nil {
        ipSet := make(map[string]struct{})
        for _, rec := range batch {
            ipSet[rec.SrcHost] = struct{}{}
            ipSet[rec.DstHost] = struct{}{}
        }

        var ipList []string
        for ip := range ipSet {
            ipList = append(ipList, ip)
        }

        bgpMap := b.bgp.FindASPathBatch(ipList)

        for _, rec := range batch {
            if len(rec.ASPath) == 0 {
                if path := bgpMap[rec.SrcHost]; len(path) > 0 {
                    rec.ASPath = path
                } else if path := bgpMap[rec.DstHost]; len(path) > 0 {
                    rec.ASPath = path
                }
            }

            if path := bgpMap[rec.SrcHost]; len(path) > 0 {
                if asn, _ := toASN(path[0]); asn > 0 {
                    rec.PeerSrcAS = asn
                    rec.PeerSrcASName = geoASNName(asn)
                }
            }

            if path := bgpMap[rec.DstHost]; len(path) > 0 {
                if asn, _ := toASN(path[0]); asn > 0 {
                    rec.PeerDstAS = asn
                    rec.PeerDstASName = geoASNName(asn)
                }
                if asn, _ := toASN(path[len(path)-1]); asn > 0 {
                    rec.DstAS = asn
                }
            }
        }
    }

    dlog("Flushing %d flows to ClickHouse", len(batch))

    if err := b.inserter.InsertBatch(context.Background(), batch); err != nil {
        log.Printf("[ERROR] Failed to insert batch: %v", err)
    }
}

func toASN(s string) (uint32, error) {
    var asn uint32
    _, err := fmt.Sscanf(s, "%d", &asn)
    return asn, err
}

var asnNameCache sync.Map

func geoASNName(asn uint32) string {
    if geo == nil || asn == 0 {
        return ""
    }

    if name, ok := asnNameCache.Load(asn); ok {
        return name.(string)
    }

    name := geo.GetASNName(fmt.Sprintf("%d", asn))
    asnNameCache.Store(asn, name)
    return name
}


func (b *InsertFlowBatcher) Close() {
    b.flushCancel()
    b.ticker.Stop()
    b.flush()
}
