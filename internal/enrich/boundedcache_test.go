package enrich

import (
	"fmt"
	"testing"
)

func TestBoundedCacheBasic(t *testing.T) {
	c := newBoundedCache(10)
	if _, ok := c.Get("a"); ok {
		t.Fatal("empty cache must miss")
	}
	c.Put("a", 1)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("expected hit a=1, got %v %v", v, ok)
	}
}

func TestBoundedCacheFlipBoundsMemory(t *testing.T) {
	c := newBoundedCache(100)
	for i := 0; i < 10_000; i++ {
		c.Put(fmt.Sprintf("ip-%d", i), i)
	}
	if n := c.Len(); n > 200 {
		t.Fatalf("cache exceeded 2x bound: %d entries", n)
	}
	// The most recent insert always survives.
	if v, ok := c.Get("ip-9999"); !ok || v != 9999 {
		t.Fatalf("latest entry must be present, got %v %v", v, ok)
	}
}

func TestBoundedCachePromotionSurvivesFlip(t *testing.T) {
	c := newBoundedCache(100)
	c.Put("hot", "x")
	// Fill to force a flip: "hot" moves to the previous generation.
	for i := 0; i < 100; i++ {
		c.Put(fmt.Sprintf("k%d", i), i)
	}
	// A hit in the previous generation promotes it into the current one.
	if _, ok := c.Get("hot"); !ok {
		t.Fatal("hot entry must still be readable after one flip")
	}
	// Force one more flip; the promoted entry lands in the previous
	// generation and must still be readable. (An entry never read between
	// two consecutive flips is dropped — that is the eviction policy.)
	for i := 0; i < 100; i++ {
		c.Put(fmt.Sprintf("j%d", i), i)
	}
	if _, ok := c.Get("hot"); !ok {
		t.Fatal("promoted hot entry must survive the next flip")
	}
}

func TestBoundedCacheUnlimited(t *testing.T) {
	c := newBoundedCache(0) // negative config → 0 internally → never flips
	for i := 0; i < 5_000; i++ {
		c.Put(fmt.Sprintf("ip-%d", i), i)
	}
	if n := c.Len(); n != 5_000 {
		t.Fatalf("unlimited cache must keep everything, got %d", n)
	}
}
