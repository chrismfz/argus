package debugcli

import (
	"math"
	"strings"
	"testing"
)

// A minimal but structurally faithful debug=1 heap profile: header with the
// 2×sample-rate, two records with symbolized frames, and the MemStats trailer
// that must not confuse the parser.
const sampleHeapDebug1 = `heap profile: 3: 2097152 [10: 5242880] @ heap/1048576
1: 1048576 [1: 1048576] @ 0x4a2e35 0x4a2d17 0x4b0001
#	0x4a2e34	runtime.mapassign_fast64+0x54	/usr/local/go/src/runtime/map_fast64.go:92
#	0x4a2d16	argus/internal/telemetry.(*Aggregator).Ingest+0x96	/home/user/argus/internal/telemetry/aggregator.go:213
#	0x4b0000	main.main+0x100	/home/user/argus/cmd/argus/main.go:95

2: 1048576 [9: 4194304] @ 0x4c0001 0x4c0002
#	0x4c0000	github.com/yl2chen/cidranger.(*prefixTrie).Insert+0x20	/go/pkg/mod/trie.go:10
#	0x4c0001	argus/internal/bgp.(*BGPListener).watchUpdates+0x30	/home/user/argus/internal/bgp/daemon.go:286

# runtime.MemStats
# Alloc = 123456
# TotalAlloc = 234567
`

func TestParseHeapDebug1(t *testing.T) {
	sites, total := parseHeapDebug1(sampleHeapDebug1)
	if len(sites) != 2 {
		t.Fatalf("expected 2 aggregated sites, got %d: %+v", len(sites), sites)
	}
	if total <= 0 {
		t.Fatalf("expected positive total, got %f", total)
	}

	// Frame selection must skip the runtime.* leaf and pick the argus frame.
	bySite := map[string]heapSite{}
	for _, s := range sites {
		bySite[s.Site] = s
	}
	if _, ok := bySite["argus/internal/telemetry.(*Aggregator).Ingest"]; !ok {
		t.Errorf("expected telemetry.Ingest site (runtime leaf skipped), got %+v", sites)
	}
	if _, ok := bySite["github.com/yl2chen/cidranger.(*prefixTrie).Insert"]; !ok {
		t.Errorf("expected cidranger Insert site, got %+v", sites)
	}

	// Scaling: record 1 has avg = 1 MiB with rate 512 KiB → scale = 1/(1-e^-2).
	rate := 1048576.0 / 2
	want := 1048576.0 / (1 - math.Exp(-1048576.0/rate))
	got := bySite["argus/internal/telemetry.(*Aggregator).Ingest"].InuseBytes
	if math.Abs(got-want) > 1 {
		t.Errorf("scaled inuse bytes = %f, want %f", got, want)
	}

	// Sorted descending by in-use bytes.
	if sites[0].InuseBytes < sites[1].InuseBytes {
		t.Errorf("sites not sorted descending: %+v", sites)
	}
}

func TestParseHeapDebug1Empty(t *testing.T) {
	sites, total := parseHeapDebug1("")
	if len(sites) != 0 || total != 0 {
		t.Fatalf("empty input should parse to nothing, got %d sites total=%f", len(sites), total)
	}
}

func TestParseSampleHeader(t *testing.T) {
	n, b, an, ab, ok := parseSampleHeader("1: 29081600 [5: 145408000] @ 0x1 0x2")
	if !ok || n != 1 || b != 29081600 || an != 5 || ab != 145408000 {
		t.Fatalf("parseSampleHeader = %d %d %d %d %v", n, b, an, ab, ok)
	}
	if _, _, _, _, ok := parseSampleHeader("# Alloc = 123"); ok {
		t.Fatal("MemStats trailer line must not parse as a sample")
	}
	if _, _, _, _, ok := parseSampleHeader("garbage"); ok {
		t.Fatal("garbage must not parse as a sample")
	}
}

func TestRenderHeapTop(t *testing.T) {
	sites := []heapSite{
		{Site: "a.B", InuseBytes: 2 << 30, InuseObjs: 10},
		{Site: "c.D", InuseBytes: 1 << 20, InuseObjs: 5},
	}
	out := renderHeapTop(sites, (2<<30)+(1<<20), 20)
	if !strings.Contains(out, "a.B") || !strings.Contains(out, "GiB") {
		t.Fatalf("unexpected render output:\n%s", out)
	}
}
