package main

import (
	"context"
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
}

func NewInsertFlowBatcher(inserter *ClickHouseInserter, batchSize int, flushInterval time.Duration) *InsertFlowBatcher {
	ctx, cancel := context.WithCancel(context.Background())
	b := &InsertFlowBatcher{
		inserter:      inserter,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		buffer:        make([]*FlowRecord, 0, batchSize),
		ticker:        time.NewTicker(flushInterval),
		flushCtx:      ctx,
		flushCancel:   cancel,
	}
	go b.autoFlushLoop()
	return b
}

func (b *InsertFlowBatcher) Add(flow *FlowRecord) {
	b.lock.Lock()
	b.buffer = append(b.buffer, flow)
	shouldFlush := len(b.buffer) >= b.batchSize
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
	batch := b.buffer
	b.buffer = make([]*FlowRecord, 0, b.batchSize)
	b.lock.Unlock()

	if len(batch) == 0 {
		return
	}

	dlog("Flushing %d flows to ClickHouse", len(batch))

	err := b.inserter.InsertBatch(context.Background(), batch)
	if err != nil {
		log.Printf("[ERROR] Failed to insert batch: %v", err)
	}
}

func (b *InsertFlowBatcher) Close() {
	b.flushCancel()
	b.ticker.Stop()
	b.flush()
}
