package debugcli

// Parser for the legacy text heap profile (`/debug/pprof/heap?debug=1`).
//
// The point: produce a "top allocation sites by in-use bytes" table WITHOUT
// needing `go tool pprof` on the production host. The debug=1 format carries
// symbolized stacks inline, so the summary can be built from a plain HTTP
// fetch. Values are un-sampled with the same statistical scaling pprof's
// legacy parser applies (each sample of avg size s, sampled at rate r, is
// scaled by 1/(1-exp(-s/r))).

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// heapSite is one aggregated allocation site.
type heapSite struct {
	Site       string  // symbol of the chosen frame
	InuseBytes float64 // scaled estimate
	InuseObjs  float64
	AllocBytes float64 // scaled lifetime allocations
}

// parseHeapDebug1 parses the debug=1 heap profile text and returns allocation
// sites aggregated by their most meaningful frame, sorted by in-use bytes
// descending, plus the scaled totals.
func parseHeapDebug1(text string) (sites []heapSite, totalInuse float64) {
	lines := strings.Split(text, "\n")
	rate := float64(512 * 1024) // runtime default MemProfileRate
	agg := map[string]*heapSite{}

	var cur *heapSite // site pending frame selection
	var curFrames []string

	flush := func() {
		if cur == nil {
			return
		}
		site := chooseFrame(curFrames)
		if site == "" {
			site = "(unsymbolized)"
		}
		a, ok := agg[site]
		if !ok {
			a = &heapSite{Site: site}
			agg[site] = a
		}
		a.InuseBytes += cur.InuseBytes
		a.InuseObjs += cur.InuseObjs
		a.AllocBytes += cur.AllocBytes
		cur, curFrames = nil, nil
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "heap profile:") {
			// "heap profile: N: B [n: b] @ heap/1048576" — trailing value is
			// 2*MemProfileRate.
			if i := strings.LastIndex(line, "heap/"); i >= 0 {
				if v, err := strconv.ParseFloat(strings.TrimSpace(line[i+5:]), 64); err == nil && v > 0 {
					rate = v / 2
				}
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Symbol line: "#\t0x4a2e34\tmain.main+0x54\t/path/file.go:123"
			// The MemStats trailer also starts with "# " — its fields never
			// have the addr+symbol shape, so they fail the split below.
			f := strings.Fields(line)
			if cur != nil && len(f) >= 3 && strings.HasPrefix(f[1], "0x") {
				sym := f[2]
				if i := strings.LastIndex(sym, "+0x"); i > 0 {
					sym = sym[:i]
				}
				curFrames = append(curFrames, sym)
			}
			continue
		}
		if n, b, an, ab, ok := parseSampleHeader(line); ok {
			flush()
			// Scale sampled values to estimated true values (pprof legacy scaling).
			sb, so := scaleHeapSample(b, n, rate)
			sab, _ := scaleHeapSample(ab, an, rate)
			cur = &heapSite{InuseBytes: sb, InuseObjs: so, AllocBytes: sab}
		}
	}
	flush()

	sites = make([]heapSite, 0, len(agg))
	for _, a := range agg {
		sites = append(sites, *a)
		totalInuse += a.InuseBytes
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].InuseBytes > sites[j].InuseBytes })
	return sites, totalInuse
}

// parseSampleHeader parses "N: B [n: b] @ 0x... 0x..." → inuse objs/bytes,
// alloc objs/bytes.
func parseSampleHeader(line string) (n, b, an, ab int64, ok bool) {
	at := strings.Index(line, " @ ")
	if at < 0 {
		return 0, 0, 0, 0, false
	}
	head := line[:at]
	// "N: B [n: b]"
	head = strings.ReplaceAll(head, "[", "")
	head = strings.ReplaceAll(head, "]", "")
	head = strings.ReplaceAll(head, ":", "")
	f := strings.Fields(head)
	if len(f) != 4 {
		return 0, 0, 0, 0, false
	}
	vals := make([]int64, 4)
	for i, s := range f {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, 0, 0, 0, false
		}
		vals[i] = v
	}
	return vals[0], vals[1], vals[2], vals[3], true
}

// scaleHeapSample applies pprof's statistical un-sampling: with Poisson
// sampling at `rate` bytes, a sample of average size s represents
// 1/(1-exp(-s/rate)) true samples.
func scaleHeapSample(bytes, count int64, rate float64) (scaledBytes, scaledCount float64) {
	if count == 0 || bytes == 0 {
		return 0, 0
	}
	if rate <= 1 {
		return float64(bytes), float64(count)
	}
	avg := float64(bytes) / float64(count)
	scale := 1 / (1 - math.Exp(-avg/rate))
	return float64(bytes) * scale, float64(count) * scale
}

// chooseFrame picks the most informative frame of a stack: the first
// (deepest) frame that isn't runtime/GC plumbing. Falls back to the leaf.
func chooseFrame(frames []string) string {
	for _, f := range frames {
		if !isBoringFrame(f) {
			return f
		}
	}
	if len(frames) > 0 {
		return frames[0]
	}
	return ""
}

func isBoringFrame(sym string) bool {
	for _, p := range []string{
		"runtime.", "runtime/", "sync.", "sync/", "internal/",
		"reflect.", "aeshash", "strings.(*Builder)",
	} {
		if strings.HasPrefix(sym, p) {
			return true
		}
	}
	return false
}

// renderHeapTop renders the top-N table for summary.txt / stdout.
func renderHeapTop(sites []heapSite, total float64, n int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-12s %8s %12s  %s\n", "INUSE", "%TOT", "OBJECTS", "ALLOCATION SITE")
	for i, s := range sites {
		if i >= n || s.InuseBytes <= 0 {
			break
		}
		pct := 0.0
		if total > 0 {
			pct = 100 * s.InuseBytes / total
		}
		fmt.Fprintf(&sb, "%-12s %7.1f%% %12.0f  %s\n",
			humanBytes(s.InuseBytes), pct, s.InuseObjs, s.Site)
	}
	fmt.Fprintf(&sb, "%-12s %7s %12s  (total in-use heap, estimated from samples)\n",
		humanBytes(total), "100%", "")
	return sb.String()
}

func humanBytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", b/(1<<10))
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}
