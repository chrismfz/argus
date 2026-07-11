package detection

import (
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-test DetectionStore. It records IncrementCount calls and
// can optionally block inside IncrementCount to simulate slow action I/O
// (BGP announce / PTR DNS / SQLite) so we can assert the ingest path is not
// stalled behind it.
type fakeStore struct {
	mu     sync.Mutex
	calls  []string
	counts map[string]int

	entered chan struct{} // signalled once when IncrementCount is entered
	release chan struct{} // IncrementCount blocks until this is closed (if non-nil)
}

func newFakeStore() *fakeStore {
	return &fakeStore{counts: map[string]int{}}
}

func (f *fakeStore) IncrementCount(rule, ip string) (int, error) {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := rule + "/" + ip
	f.calls = append(f.calls, key)
	f.counts[key]++
	return f.counts[key], nil
}

func (f *fakeStore) GetCount(rule, ip string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[rule+"/"+ip], nil
}

func (f *fakeStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func tcpFlow(src, dst string, dstPort uint16, ts time.Time) Flow {
	return Flow{
		Timestamp: ts,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   12345,
		DstPort:   dstPort,
		Proto:     "tcp",
		Packets:   1,
		Bytes:     100,
	}
}

// Action is left empty in these tests so a matched rule exercises the store
// (the blocking seam) without triggering the alert/blackhole side effects,
// which would dereference the nil Geo/DNS enrichers.

func TestRunDetectionMatchIncrementsStore(t *testing.T) {
	store := newFakeStore()
	rule := DetectionRule{
		Name:       "test_tcp",
		Proto:      "tcp",
		MinFlows:   2,
		TimeWindow: "10s",
		Action:     "",
	}
	e := NewEngine([]DetectionRule{rule}, 65000, nil, time.Minute, nil, nil, store)

	now := time.Now()
	e.AddFlow(tcpFlow("1.2.3.4", "5.6.7.8", 80, now))
	e.AddFlow(tcpFlow("1.2.3.4", "5.6.7.9", 80, now))

	e.runDetection()

	if got := store.callCount(); got != 1 {
		t.Fatalf("expected 1 IncrementCount call for a matching rule, got %d", got)
	}
	if c, _ := store.GetCount("test_tcp", "1.2.3.4"); c != 1 {
		t.Fatalf("expected count 1 for the triggering IP, got %d", c)
	}
}

func TestRunDetectionNoMatchDoesNotIncrement(t *testing.T) {
	store := newFakeStore()
	rule := DetectionRule{
		Name:       "test_tcp",
		Proto:      "tcp",
		MinFlows:   5, // more than we will feed
		TimeWindow: "10s",
	}
	e := NewEngine([]DetectionRule{rule}, 65000, nil, time.Minute, nil, nil, store)

	e.AddFlow(tcpFlow("1.2.3.4", "5.6.7.8", 80, time.Now()))
	e.runDetection()

	if got := store.callCount(); got != 0 {
		t.Fatalf("expected no IncrementCount calls when the rule does not match, got %d", got)
	}
}

// TestRunDetectionDoesNotHoldLockDuringActions is the regression test for the
// Phase 0 lock hazard: runDetection must release e.mu before executing per-rule
// work (IncrementCount / LogDetection / HandleBlackhole), otherwise a slow
// action blocks AddFlow on the ingest hot path. We block inside the store to
// simulate a slow action and assert AddFlow still proceeds concurrently.
func TestRunDetectionDoesNotHoldLockDuringActions(t *testing.T) {
	store := newFakeStore()
	store.entered = make(chan struct{}, 1)
	store.release = make(chan struct{})

	rule := DetectionRule{
		Name:       "test_tcp",
		Proto:      "tcp",
		MinFlows:   2,
		TimeWindow: "10s",
	}
	e := NewEngine([]DetectionRule{rule}, 65000, nil, time.Minute, nil, nil, store)

	now := time.Now()
	e.AddFlow(tcpFlow("1.2.3.4", "5.6.7.8", 80, now))
	e.AddFlow(tcpFlow("1.2.3.4", "5.6.7.9", 80, now))

	done := make(chan struct{})
	go func() {
		e.runDetection() // will block inside store.IncrementCount
		close(done)
	}()

	select {
	case <-store.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("runDetection never reached IncrementCount")
	}

	// The action is now in flight (blocked). AddFlow must not be blocked by it.
	addReturned := make(chan struct{})
	go func() {
		e.AddFlow(tcpFlow("9.9.9.9", "5.6.7.8", 80, time.Now()))
		close(addReturned)
	}()

	select {
	case <-addReturned:
		// good: ingest proceeds while the action runs
	case <-time.After(2 * time.Second):
		close(store.release) // unblock so the goroutine does not leak
		t.Fatal("AddFlow blocked while a detection action was running — e.mu held across actions")
	}

	close(store.release)
	<-done
}
