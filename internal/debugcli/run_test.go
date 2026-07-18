package debugcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPruneBundles(t *testing.T) {
	root := t.TempDir()
	names := []string{
		"20260101T000000Z", "20260102T000000Z", "20260103T000000Z",
		"20260104T000000Z", "not-a-bundle",
	}
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(root, n), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	pruneBundles(root, 2)

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	// Newest two kept, non-conforming dir untouched.
	for _, want := range []string{"20260103T000000Z", "20260104T000000Z", "not-a-bundle"} {
		if !got[want] {
			t.Errorf("expected %s to survive pruning, remaining: %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("expected 3 survivors, got %v", got)
	}
}

func TestBuildSummaryDegradesWithoutAPI(t *testing.T) {
	out := buildSummary(nil, nil, 0, map[string]string{"memstats.json": "error: connection refused"})
	if out == "" {
		t.Fatal("summary must render even with no data")
	}
}

func TestBuildSummaryWithCensus(t *testing.T) {
	memstats := []byte(`{
		"goroutines": 42, "uptime_sec": 60,
		"process": {"vmrss_kb": 1048576, "vmsize_kb": 2097152},
		"go_mem": {"heap_inuse": 1073741824, "heap_idle": 0, "heap_released": 0, "sys": 2147483648, "heap_objects": 100, "num_gc": 5},
		"components": {"bgp": {"ranger_paths": 1000000}}
	}`)
	out := buildSummary(memstats, nil, 0, map[string]string{})
	for _, want := range []string{"Process RSS", "1.00 GiB", "ranger_paths"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}
