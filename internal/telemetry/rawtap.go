package telemetry

import (
	"encoding/json"
	"sync"
	"time"
)

// RawRecord is one raw NetFlow/IPFIX record exactly as it came off the wire.
// Keys are IANA field IDs (uint16), values are .ToString() of the raw bytes.
type RawRecord struct {
	Ts     int64             `json:"ts"`
	Source string            `json:"source"` // sender IP:port
	Fields map[uint16]string `json:"fields"`
}

// RawFlowTap is a second SSE broadcaster for raw records.
var RawTap = &rawFlowTap{
	clients: make(map[chan []byte]struct{}),
	ring:    make([][]byte, 64),
	ringLen: 64,
}

type rawFlowTap struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
	ring    [][]byte
	ringPos int
	ringLen int
}

func (t *rawFlowTap) Subscribe() chan []byte {
	ch := make(chan []byte, 128)
	t.mu.Lock()
	for i := 0; i < t.ringLen; i++ {
		pos := (t.ringPos + i) % t.ringLen
		if t.ring[pos] != nil {
			ch <- t.ring[pos]
		}
	}
	t.clients[ch] = struct{}{}
	t.mu.Unlock()
	return ch
}

func (t *rawFlowTap) Unsubscribe(ch chan []byte) {
	t.mu.Lock()
	delete(t.clients, ch)
	t.mu.Unlock()
	close(ch)
}

func (t *rawFlowTap) Publish(source string, fields map[uint16]string) {
	rec := RawRecord{
		Ts:     time.Now().Unix(),
		Source: source,
		Fields: fields,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line := append([]byte("data: "), b...)
	line = append(line, '\n', '\n')

	t.mu.Lock()
	t.ring[t.ringPos%t.ringLen] = line
	t.ringPos++
	for ch := range t.clients {
		select {
		case ch <- line:
		default:
		}
	}
	t.mu.Unlock()
}
