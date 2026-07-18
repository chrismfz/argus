// Package debugcli implements `argus debug` — a one-shot diagnostic capture
// for the running daemon, modeled on cfm's `cfm debug`.
//
// It produces a directory <output>/<UTC-timestamp>/ containing:
//
//	memstats.json        /debug/memstats — Go runtime stats + component census
//	heap.pb.gz           binary heap profile (for `go tool pprof` offline)
//	heap-inuse.txt       symbolized heap profile (readable without tooling)
//	allocs.pb.gz         binary allocs profile
//	goroutines.txt       goroutine dump (debug=1, counts by stack)
//	goroutines-full.txt  goroutine dump (debug=2, full stacks)
//	cpu.pb.gz            CPU profile (only with --cpu N)
//	proc-status.txt      /proc/<pid>/status of the daemon
//	summary.txt          the scannable answer: RSS vs Go heap, top allocation
//	                     sites, per-component element counts
//
// Everything is fetched over the local API (loopback is always allowed by the
// API's IP guard), so no token is needed when run on the server itself.
package debugcli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"argus/internal/config"
)

const bundleTimeFormat = "20060102T150405Z"

type opts struct {
	configPath string
	apiBase    string
	outputRoot string
	cpuSeconds int
	keep       int
	noPprof    bool
}

// Run is the entry point invoked from cmd/argus for `argus debug`.
// args is os.Args[2:]. Returns the process exit code.
func Run(args []string) int {
	o, err := parseFlags(args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, "argus debug:", err)
		return 2
	}
	if o.apiBase == "" {
		o.apiBase = discoverAPIBase(o.configPath)
	}

	bundle := filepath.Join(o.outputRoot, time.Now().UTC().Format(bundleTimeFormat))
	if err := os.MkdirAll(bundle, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "argus debug: cannot create %s: %v\n", bundle, err)
		return 1
	}
	fmt.Printf("argus debug: writing bundle to %s (api: %s)\n\n", bundle, o.apiBase)

	status := map[string]string{}
	save := func(name string, data []byte, err error) {
		if err != nil {
			status[name] = "error: " + err.Error()
			return
		}
		if werr := os.WriteFile(filepath.Join(bundle, name), data, 0o600); werr != nil {
			status[name] = "error: " + werr.Error()
			return
		}
		status[name] = fmt.Sprintf("ok (%d bytes)", len(data))
	}

	// 1) Census + memstats — the core capture.
	memstatsRaw, memErr := fetch(o.apiBase+"/debug/memstats", 15*time.Second)
	save("memstats.json", memstatsRaw, memErr)

	// 2) pprof captures.
	var heapDebug []byte
	if !o.noPprof {
		b, err := fetch(o.apiBase+"/debug/pprof/heap", 20*time.Second)
		save("heap.pb.gz", b, err)

		heapDebug, err = fetch(o.apiBase+"/debug/pprof/heap?debug=1", 30*time.Second)
		save("heap-inuse.txt", heapDebug, err)

		b, err = fetch(o.apiBase+"/debug/pprof/allocs", 20*time.Second)
		save("allocs.pb.gz", b, err)

		b, err = fetch(o.apiBase+"/debug/pprof/goroutine?debug=1", 15*time.Second)
		save("goroutines.txt", b, err)

		b, err = fetch(o.apiBase+"/debug/pprof/goroutine?debug=2", 15*time.Second)
		save("goroutines-full.txt", b, err)

		if o.cpuSeconds > 0 {
			fmt.Printf("capturing CPU profile (%ds)...\n", o.cpuSeconds)
			b, err = fetch(fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", o.apiBase, o.cpuSeconds),
				time.Duration(o.cpuSeconds)*time.Second+15*time.Second)
			save("cpu.pb.gz", b, err)
		}
	} else {
		status["pprof"] = "skipped: --no-pprof"
	}

	// 3) Daemon /proc snapshot (independent of the API being up).
	pid := findDaemonPID()
	if pid > 0 {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		save("proc-status.txt", b, err)
	} else {
		status["proc-status.txt"] = "skipped: argus daemon process not found"
	}

	// 4) Summary.
	summary := buildSummary(memstatsRaw, heapDebug, pid, status)
	save("summary.txt", []byte(summary), nil)

	// 5) Prune old bundles.
	if o.keep > 0 {
		pruneBundles(o.outputRoot, o.keep)
	}

	fmt.Print(summary)
	fmt.Printf("\nBundle complete: %s\n", bundle)
	if memErr != nil {
		fmt.Fprintf(os.Stderr, "\nWARNING: /debug/memstats unreachable (%v) — is the daemon running and the API on %s?\n", memErr, o.apiBase)
		return 1
	}
	return 0
}

func parseFlags(args []string) (*opts, error) {
	fs := flag.NewFlagSet("argus debug", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgFlag := fs.String("config", "", "config file used to discover the API address (default: auto-detect)")
	apiFlag := fs.String("api", "", "API base URL (default: from config, else http://127.0.0.1:9600)")
	outFlag := fs.String("output", "debug-bundles", "bundle root directory; bundle goes to <root>/<UTC-timestamp>")
	cpuFlag := fs.Int("cpu", 0, "also capture a CPU profile of N seconds (0 = skip, memory captures are instant)")
	keepFlag := fs.Int("keep", 10, "retain only the last N bundles in the output dir; 0 disables pruning")
	noPprof := fs.Bool("no-pprof", false, "skip pprof captures (API down); still snapshots /proc")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: argus debug [flags]

One-shot diagnostic bundle: memory census + pprof profiles + summary.
Run it on the server next to the daemon; loopback needs no token.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *cpuFlag < 0 || *cpuFlag > 300 {
		return nil, fmt.Errorf("--cpu must be between 0 and 300 seconds")
	}
	return &opts{
		configPath: *cfgFlag,
		apiBase:    strings.TrimRight(*apiFlag, "/"),
		outputRoot: *outFlag,
		cpuSeconds: *cpuFlag,
		keep:       *keepFlag,
		noPprof:    *noPprof,
	}, nil
}

// discoverAPIBase reads the API port from the config file. Bind addresses
// like "" or 0.0.0.0 are reached via loopback (always allowed by the IP guard).
func discoverAPIBase(configPath string) string {
	base := "http://127.0.0.1:9600"
	if configPath == "" {
		p, err := config.GetDefaultConfigPath()
		if err != nil {
			return base
		}
		configPath = p
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil || cfg.API.Port == 0 {
		return base
	}
	host := strings.TrimSpace(cfg.API.ListenAddress)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d", host, cfg.API.Port)
}

func fetch(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// findDaemonPID scans /proc for the argus daemon: comm == "argus", not this
// process, and not another `argus debug` invocation.
func findDaemonPID() int {
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil || strings.TrimSpace(string(comm)) != "argus" {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if strings.Contains(string(cmdline), "debug\x00") || strings.Contains(string(cmdline), "auth\x00") {
			continue
		}
		return pid
	}
	return 0
}

// pruneBundles deletes all but the newest `keep` timestamp-named directories.
func pruneBundles(root string, keep int) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := time.Parse(bundleTimeFormat, e.Name()); err == nil {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names) // timestamp format sorts chronologically
	for _, drop := range names[:len(names)-keep] {
		_ = os.RemoveAll(filepath.Join(root, drop))
	}
}

// ── summary ──────────────────────────────────────────────────────────────────

func buildSummary(memstatsRaw, heapDebug []byte, pid int, status map[string]string) string {
	var sb strings.Builder
	sb.WriteString("═══ argus debug summary ═══\n\n")

	var ms map[string]any
	if len(memstatsRaw) > 0 {
		_ = json.Unmarshal(memstatsRaw, &ms)
	}

	// Process / runtime overview.
	if ms != nil {
		if proc, ok := ms["process"].(map[string]any); ok {
			rss := num(proc["vmrss_kb"]) * 1024
			vsz := num(proc["vmsize_kb"]) * 1024
			fmt.Fprintf(&sb, "Process RSS:      %s   (VmSize %s)\n", humanBytes(rss), humanBytes(vsz))
		}
		if gm, ok := ms["go_mem"].(map[string]any); ok {
			heapInuse := num(gm["heap_inuse"])
			heapIdle := num(gm["heap_idle"])
			released := num(gm["heap_released"])
			fmt.Fprintf(&sb, "Go heap in-use:   %s   (idle %s, of which released to OS %s)\n",
				humanBytes(heapInuse), humanBytes(heapIdle), humanBytes(released))
			fmt.Fprintf(&sb, "Go runtime sys:   %s   heap objects: %.0f   GC runs: %.0f\n",
				humanBytes(num(gm["sys"])), num(gm["heap_objects"]), num(gm["num_gc"]))
		}
		fmt.Fprintf(&sb, "Goroutines:       %.0f   Uptime: %s\n",
			num(ms["goroutines"]), (time.Duration(num(ms["uptime_sec"])) * time.Second).String())
	} else if pid > 0 {
		fmt.Fprintf(&sb, "API unreachable — only /proc/%d/status captured.\n", pid)
	} else {
		sb.WriteString("API unreachable and no argus daemon process found.\n")
	}

	// Top allocation sites from the symbolized heap profile.
	if len(heapDebug) > 0 {
		sites, total := parseHeapDebug1(string(heapDebug))
		if len(sites) > 0 {
			sb.WriteString("\n── Top allocation sites (in-use heap) ──\n")
			sb.WriteString(renderHeapTop(sites, total, 20))
		}
	}

	// Component census.
	if ms != nil {
		if comps, ok := ms["components"].(map[string]any); ok && len(comps) > 0 {
			sb.WriteString("\n── Component census (element counts) ──\n")
			names := make([]string, 0, len(comps))
			for k := range comps {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, name := range names {
				fields, ok := comps[name].(map[string]any)
				if !ok || len(fields) == 0 {
					continue
				}
				keys := make([]string, 0, len(fields))
				for k := range fields {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				fmt.Fprintf(&sb, "%s:\n", name)
				for _, k := range keys {
					fmt.Fprintf(&sb, "  %-24s %s\n", k, renderJSONValue(fields[k]))
				}
			}
		}
	}

	// Capture manifest.
	sb.WriteString("\n── Captures ──\n")
	keys := make([]string, 0, len(status))
	for k := range status {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, "  %-22s %s\n", k, status[k])
	}
	return sb.String()
}

// num pulls a float out of decoded JSON (numbers arrive as float64).
func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// renderJSONValue formats a decoded JSON value for the census table: whole
// floats print as plain integers (never 4.4e+06), everything else via %v.
func renderJSONValue(v any) string {
	if f, ok := v.(float64); ok && f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", v)
}
