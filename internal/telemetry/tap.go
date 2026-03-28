package telemetry

import (
	"encoding/json"
	"sync"
	"time"
)

// TapRecord is what gets broadcast to debug clients.
// Includes raw fields AND the computed direction so you can see mismatches.
type TapRecord struct {
	Ts            int64  `json:"ts"`
	SrcHost       string `json:"src"`
	DstHost       string `json:"dst"`
	DstPort       uint16 `json:"dst_port"`
	PeerSrcAS     uint32 `json:"peer_src_as"`
	PeerSrcASName string `json:"peer_src_name"`
	PeerDstAS     uint32 `json:"peer_dst_as"`
	PeerDstASName string `json:"peer_dst_name"`
	Bytes         uint64 `json:"bytes"`
	Packets       uint64 `json:"packets"`
	FlowDirection uint8  `json:"flow_dir_raw"`   // raw value from MikroTik
	Inbound       bool   `json:"inbound"`         // computed by isInbound()
	SrcInMyNets   bool   `json:"src_in_my_nets"` // debug: src matched my_prefixes
	DstInMyNets   bool   `json:"dst_in_my_nets"` // debug: dst matched my_prefixes
}

// FlowTap is a lock-free SSE broadcaster.
// Subscribers receive a channel of pre-serialised JSON lines.
type FlowTap struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}

	// recent holds the last ringLen records for late-joining clients
	ring    [][]byte
	ringPos int
	ringLen int
}

var Tap = &FlowTap{
	clients: make(map[chan []byte]struct{}),
	ring:    make([][]byte, 128),
	ringLen: 128,
}

// Subscribe returns a channel that receives SSE-formatted lines.
// The caller must call Unsubscribe when done.
func (t *FlowTap) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	t.mu.Lock()
	// replay recent records so the page isn't empty on connect
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

// Unsubscribe removes a subscriber and closes its channel.
func (t *FlowTap) Unsubscribe(ch chan []byte) {
	t.mu.Lock()
	delete(t.clients, ch)
	t.mu.Unlock()
	close(ch)
}

// publish sends a record to all connected clients.
func (t *FlowTap) publish(rec TapRecord) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	// SSE format: "data: {...}\n\n"
	line := append([]byte("data: "), b...)
	line = append(line, '\n', '\n')

	t.mu.Lock()
	// store in ring
	t.ring[t.ringPos%t.ringLen] = line
	t.ringPos++
	// fan out — non-blocking, drop if client is slow
	for ch := range t.clients {
		select {
		case ch <- line:
		default:
		}
	}
	t.mu.Unlock()
}

// ingest is called from Aggregator.Ingest with the computed direction fields.
func (t *FlowTap) ingest(rec *Record, inbound, srcInMy, dstInMy bool) {
	t.publish(TapRecord{
		Ts:            time.Now().Unix(),
		SrcHost:       rec.SrcHost,
		DstHost:       rec.DstHost,
		DstPort:       rec.DstPort,
		PeerSrcAS:     rec.PeerSrcAS,
		PeerSrcASName: rec.PeerSrcASName,
		PeerDstAS:     rec.PeerDstAS,
		PeerDstASName: rec.PeerDstASName,
		Bytes:         rec.Bytes,
		Packets:       rec.Packets,
		FlowDirection: rec.FlowDirection,
		Inbound:       inbound,
		SrcInMyNets:   srcInMy,
		DstInMyNets:   dstInMy,
	})
}
