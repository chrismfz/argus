package enrich

import "sync"

// boundedCache is a two-generation bounded map used for the per-IP GeoIP
// caches. The previous sync.Map caches grew one entry per distinct IP seen
// with no TTL and no cap — on a box enriching internet-wide NetFlow that is
// unbounded growth over weeks of uptime (the 6→16 GB RSS ratchet).
//
// Design: inserts go to the current generation; when it reaches max, the
// current generation becomes the previous one and a fresh map starts (the old
// previous generation is dropped and GC'd). Lookups check both generations and
// promote previous-generation hits, so hot entries survive flips. Memory is
// bounded at ~2×max entries with O(1) operations and no background sweeper.
type boundedCache struct {
	mu   sync.RWMutex
	max  int // per-generation cap; <=0 = unlimited (never flips)
	cur  map[string]any
	prev map[string]any
}

func newBoundedCache(max int) *boundedCache {
	return &boundedCache{max: max, cur: make(map[string]any)}
}

// Get returns the cached value. Hits in the previous generation are promoted
// to the current one so frequently-seen IPs are not evicted by a flip.
func (c *boundedCache) Get(k string) (any, bool) {
	c.mu.RLock()
	if v, ok := c.cur[k]; ok {
		c.mu.RUnlock()
		return v, true
	}
	v, ok := c.prev[k]
	c.mu.RUnlock()
	if ok {
		c.Put(k, v)
		return v, true
	}
	return nil, false
}

func (c *boundedCache) Put(k string, v any) {
	c.mu.Lock()
	if c.max > 0 && len(c.cur) >= c.max {
		if _, exists := c.cur[k]; !exists {
			c.prev = c.cur
			c.cur = make(map[string]any, c.max/4)
		}
	}
	c.cur[k] = v
	c.mu.Unlock()
}

// Len reports the total entries across both generations (census metric).
func (c *boundedCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cur) + len(c.prev)
}
