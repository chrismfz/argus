package detection

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
	"flowenricher/enrich"
)

type AnomalyConfig struct {
	Window        time.Duration // aggregation window (e.g., 60s)
	Interval      time.Duration // how often to score (e.g., 10s)
	Label         string        // "iforest_anomaly"
	MinScore      float64       // anomaly score threshold (0..1)
	LogOnly       bool          // true = never escalate
        Debug         bool          // when true, log extra DEBUG info (top_score, candidates)
        DebugAll      bool          // NEW: log every candidate line to anomalies.log (no gating)
	// iForest training
	RetrainEvery  time.Duration // e.g., 5m
	BaselineMax   int           // cap baseline vectors (e.g., 20000)

	TopK          int            // optional: max anomalies to log per tick (0 = no cap)

	// optional blackhole escalation (later)
	BlackholeCount int
	BlackholeTime  interface{}

        // NEW: noise controls / fusion
        UseIFLabel              bool     // if false, ignore detector's label() and use thresholds only
        RequireHBOSPercentile   float64  // HBOS gate on normalized percentile
        RequireEHBOSPercentile  float64  // eHBOS gate on normalized percentile
        // Fusion weights (fused = w_iforest*if + w_hbos*hbos_norm + w_ehbos*ehbos_norm)
        Weights struct {
                IForest float64
                HBOS    float64
		EHBOS   float64
        }
        // Mean-based printing to risk.log (percent above mean of fused in this tick)
        PrintAboveMeanPercent float64 // e.g., 25 -> mean*1.25 threshold for risk.log
        RiskLogPath           string  // optional override; default "risk.log"

        // Optional allowlist knobs (cheap, best-effort)
        AllowASNs      []uint32 // sources with these ASNs are ignored unless very strong


}

type Anomaly struct {
	mu        sync.Mutex
	bySrc     map[string]*srcWindow
	cfg       AnomalyConfig
	detector  Detector
        hbos      *HBOS
        ehbos     *EHBOS
	store     DetectionStore
	engine    *Engine

	memory    *MemoryLayer

	baseline [][]float64
	lastTrain time.Time

    // hot-reload plumbing
    cfgUpdate chan AnomalyConfig
    ticker    *time.Ticker

}


// Optional: hold runtime prefilter thresholds (attach to Anomaly if you use them)
type Prefilter struct {
    MinPPS, MinUniqDstPorts, MinUniqDstIPs, MinSynRatio, MinICMPShare float64
}

func (a *Anomaly) UpdateConfig(newCfg AnomalyConfig) {
    // push to Start() loop; it will swap the ticker and cfg atomically
    select {
    case a.cfgUpdate <- newCfg:
    default:
        // if channel is full, drop the older pending update
        <-a.cfgUpdate
        a.cfgUpdate <- newCfg
    }

}


// NEW: small helper to fetch cached enrich data safely
func getEnrichLabels(ip string) (asn uint32, asnName, cc, ptr string) {
    if enrich.Global != nil {
        if enrich.Global.Geo != nil {
            asn = enrich.Global.Geo.GetASNNumber(ip)
            asnName = enrich.Global.Geo.GetASNName(ip)
            cc = enrich.Global.Geo.GetCountry(ip)
        }
        if enrich.Global.DNS != nil {
            ptr = enrich.Global.DNS.LookupPTR(ip)
        }
    }
    if asnName == "" { asnName = "Unknown" }
    if cc == "" { cc = "--" }
    if ptr == "" { ptr = "-" }
    return
}


// helper: check if an ASN is allowlisted
func (a *Anomaly) isAllowedASN(asn uint32) bool {
    if len(a.cfg.AllowASNs) == 0 { return false }
    for _, allowed := range a.cfg.AllowASNs {
        if asn == allowed { return true }
    }
    return false
}


// helper: are models trained at least once?
func (a *Anomaly) isTrained() bool {
    // iForest: trained when lastTrain is non-zero
    if a.lastTrain.IsZero() { return false }
    // HBOS: trained when it has any training scores
    if a.hbos != nil && len(a.hbos.trainScores) == 0 { return false }
    return true
}


func (a *Anomaly) RebuildDetector(trees, sample int, contamination float64) {
    a.mu.Lock()
    // swap detector & force retrain on next tick from baseline
    a.detector = NewIForestDetector(trees, sample, contamination)
    a.lastTrain = time.Time{} // force immediate retrain if enough baseline
    a.mu.Unlock()
}

// Wire in the EWMA/debt risk logger
func (a *Anomaly) SetMemory(m *MemoryLayer) { a.memory = m }


func NewAnomaly(cfg AnomalyConfig, det Detector, store DetectionStore) *Anomaly {
	if cfg.Window <= 0 { cfg.Window = 60 * time.Second }
	if cfg.Interval <= 0 { cfg.Interval = 10 * time.Second }
	if cfg.Label == "" { cfg.Label = "iforest_anomaly" }
	if cfg.RetrainEvery <= 0 { cfg.RetrainEvery = 5 * time.Minute }
	if cfg.BaselineMax <= 0 { cfg.BaselineMax = 50000 }
	if cfg.MinScore <= 0 { cfg.MinScore = 0.70 }
        // sensible defaults
        if cfg.RequireHBOSPercentile < 0 { cfg.RequireHBOSPercentile = 0 }
        if cfg.Weights.IForest == 0 && cfg.Weights.HBOS == 0 && cfg.Weights.EHBOS == 0 {
                cfg.Weights.IForest, cfg.Weights.EHBOS, cfg.Weights.HBOS = 0.55, 0.30, 0.15
        }
        // normalize weights
        wsum := cfg.Weights.IForest + cfg.Weights.HBOS + cfg.Weights.EHBOS
        if wsum > 0 {
                cfg.Weights.IForest /= wsum
                cfg.Weights.HBOS    /= wsum
                cfg.Weights.EHBOS   /= wsum
        }

        if cfg.PrintAboveMeanPercent < 0 {
                cfg.PrintAboveMeanPercent = 0
        }
        // risk log path (optional)
        if cfg.RiskLogPath != "" {
                SetRiskLogPath(cfg.RiskLogPath)
        }

	return &Anomaly{
		bySrc:    make(map[string]*srcWindow),
		cfg:      cfg,
		detector: det,
                hbos:     NewHBOS(15, 1e-6),
                // default eHBOS: 12 subspaces of size 3, agg="max"
                ehbos:    NewEHBOS(12, 1e-6, 12, 3, "max", 7),
		store:    store,
		cfgUpdate: make(chan AnomalyConfig, 1),
	}
}

func (a *Anomaly) BindEngine(e *Engine) { a.engine = e }

func (a *Anomaly) AddFlow(f Flow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().UTC().Add(-a.cfg.Window)
	w := a.bySrc[f.SrcIP]
	if w == nil {
		w = &srcWindow{}
		a.bySrc[f.SrcIP] = w
	}
	w.add(f, cut)
}

func (a *Anomaly) Start(ctx context.Context) {

    a.ticker = time.NewTicker(a.cfg.Interval)
    go func() {
        defer a.ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-a.ticker.C:
                a.tick()
            case nc := <-a.cfgUpdate:
                // apply new config and rebuild ticker if interval changed
                a.mu.Lock()
                a.cfg = nc
                a.mu.Unlock()
                a.ticker.Stop()
                a.ticker = time.NewTicker(nc.Interval)
            }
        }
    }()

}

func (a *Anomaly) tick() {
	now := time.Now().UTC()
	cut := now.Add(-a.cfg.Window)

	// snapshot keys
	a.mu.Lock()
	keys := make([]string, 0, len(a.bySrc))
	for k, w := range a.bySrc {
		w.prune(cut)
		if len(w.flows) == 0 {
			delete(a.bySrc, k)
			continue
		}
		keys = append(keys, k)
	}
	a.mu.Unlock()

	windowSec := a.cfg.Window.Seconds()

        type scored struct{
            src   string
            score float64
            fv    featureVector
            flows []Flow
        }

	top := scored{}

	// score each src
	for _, src := range keys {
		a.mu.Lock()
		w := a.bySrc[src]
		local := append([]Flow(nil), w.flows...)
		a.mu.Unlock()

		if len(local) == 0 {
			continue
		}


                // --- EARLY ALLOWLIST: skip entirely (no anomalies.log, no risk) ---
                if enrich.Global != nil && enrich.Global.Geo != nil {
                        if a.isAllowedASN(enrich.Global.Geo.GetASNNumber(src)) {
                                continue
                        }
                }


		feat := buildFeatures(local, windowSec)
		vec := log1pVec(feat.slice())

// pre-filter: skip low-signal sources to avoid noise
if feat.PktsPerSec < 5 &&
   feat.UniqDstPorts < 10 &&
   feat.UniqDstIPs   < 10 &&
   feat.TCPSYNRatio  < 0.90 &&
   feat.ICMPShare    < 0.50 {
    continue
}

		// grow baseline (bounded)
		a.mu.Lock()
		if len(a.baseline) < a.cfg.BaselineMax {
			a.baseline = append(a.baseline, append([]float64(nil), vec...))
		} else {
			pos := len(a.baseline) % a.cfg.BaselineMax
			a.baseline[pos] = append(a.baseline[pos][:0], vec...)
		}
		a.mu.Unlock()

                // --- COLD START / WARM-UP: skip scoring & logging until first training ---
                if !a.isTrained() {
                        continue
                }

		label, score := a.detector.Score(vec)


                // HBOS/eHBOS: raw + normalized percentile [0..1]
                hbosRaw, hbosNorm, hbosTau := 0.0, 0.0, 0.0
                ehRaw,  ehNorm,  ehTau    := 0.0, 0.0, 0.0
                if a.hbos != nil {

                        hbosRaw  = a.hbos.Score(vec)
                        hbosNorm = a.hbos.ScoreNorm(vec)
                        hbosTau  = a.hbos.Bound(0.99)

                }



                if score > top.score {
                    top = scored{src: src, score: score, fv: feat, flows: local}
                }

                // FUSION (pre-gate): IF + HBOS + eHBOS (normalized)
                fused := a.cfg.Weights.IForest*score +
                         a.cfg.Weights.HBOS   *hbosNorm +
                         a.cfg.Weights.EHBOS  *ehNorm
                fusedPreGate := fused

                // ---- EWMA / Risk memory runs for every scored source ----
                if a.memory != nil {
                        st, reasons, shouldLog := a.memory.Update(src, score, feat)
                        if a.cfg.Debug || shouldLog {
                                // cheap cached enrichments
                                var asn uint32
                                var asnName, cc, ptr string
                                if enrich.Global != nil {
                                        if enrich.Global.Geo != nil {
                                                asn = enrich.Global.Geo.GetASNNumber(src)
                                                asnName = enrich.Global.Geo.GetASNName(src)
                                                cc = enrich.Global.Geo.GetCountry(src)
                                        }
                                        if enrich.Global.DNS != nil {
                                                ptr = enrich.Global.DNS.LookupPTR(src)
                                        }
                                }
                                model := "IF"
                                a.memory.MaybeLog(src, score, feat, st, reasons, asn, asnName, cc, ptr, model)
                        }
                }



        // Decide whether to fire:
        // (a) optionally trust iForest label(), otherwise threshold by bound()/MinScore
        fire := false
        if a.cfg.UseIFLabel {
            fire = (label == 1)
        }
        if !fire {
            if b, ok := a.detector.(interface{ Bound() float64 }); ok {
                fire = (score >= b.Bound())
            } else {
                fire = (score >= a.cfg.MinScore)
            }
        }

        // (b) optionally AND-gate with HBOS/eHBOS percentile (normalized)
        if fire && a.cfg.RequireHBOSPercentile > 0 && a.hbos != nil {
            if hbosNorm < a.cfg.RequireHBOSPercentile {
                fire = false
            }
        }

        if fire && a.cfg.RequireEHBOSPercentile > 0 && a.ehbos != nil {
            if ehNorm < a.cfg.RequireEHBOSPercentile {
                fire = false
            }
        }


        // Always collect candidate for mean-based risk logging; optionally log all to anomalies.log
        asn, asnName, cc, ptr := getEnrichLabels(src)
        exIP, exPort, exProto, exCnt := topDstTriple(local)
        shape := explainShape(feat)

        if a.cfg.DebugAll {
            logAnomalyLine("[%s] ANOMALY label=%s fused=%.4f if=%.4f hbos_norm=%.4f ehbos_norm=%.4f hbos_raw=%.2f(τ=%.2f) ehbos_raw=%.2f(τ=%.2f) src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d shape=%v feats=%v",
                a.cfg.Label, fusedPreGate, score, hbosNorm, hbosRaw, hbosTau, src, ptr, asn, asnName, cc,
                ehNorm, ehRaw, ehTau, exIP, exPort, exProto, exCnt, shape, feat)
        }

        if fire {

			cnt, _ := a.store.IncrementCount(a.cfg.Label, src)

            logAnomalyLine("[%s] ANOMALY label=%s fused=%.4f if=%.4f hbos_norm=%.4f ehbos_norm=%.4f hbos_raw=%.2f(τ=%.2f) ehbos_raw=%.2f(τ=%.2f) src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d shape=%v feats=%v count=%d",
                nowRFC3339(), a.cfg.Label, fusedPreGate, score, hbosNorm, ehNorm, hbosRaw, hbosTau, ehRaw, ehTau,
                src, ptr, asn, asnName, cc, exIP, exPort, exProto, exCnt, shape, feat, cnt)

			if !a.cfg.LogOnly && a.engine != nil && a.cfg.BlackholeCount > 0 && cnt >= a.cfg.BlackholeCount {
				// synthesize a minimal rule for consistent TTL/escalation
				r := DetectionRule{
					Name:                 a.cfg.Label,
					TimeWindow:           a.cfg.Window.String(),
					Action:               "blackhole",
					BlackholeTime:        a.cfg.BlackholeTime,
					BlackholeCommunities: []string{"65001:666"},
				}
				ex := local[0]
				a.engine.HandleBlackhole(r, []Flow{ex}, cnt)
                                logAnomalyLine("ESCALATE blackhole src=%s count=%d", src, cnt)
			}
		}

                // Collect candidate for mean-based risk logging
        // Collect candidate for mean-based risk logging (skip allowlisted ASNs entirely)
        if !a.isAllowedASN(asn) {
            candidates = append(candidates, cand{
                        src:   src,
                        fused: fusedPreGate,
                        ifs:   score,
                        hraw:  hbosRaw,
                        hnorm: hbosNorm,
                        ehr:   ehRaw,
                        ehn:   ehNorm,
                        feat:  feat,
                        flows: local,
                        asn:   asn, asnName: asnName, cc: cc, ptr: ptr,
                        exIP: exIP, exPort: exPort, exProto: exProto, exCnt: exCnt,
                        shape: shape,
                })

 }
	}


  // --- add this debug line at the end of tick() ---

        if a.cfg.Debug && top.src != "" {
            asn, asnName, cc, ptr := getEnrichLabels(top.src) // NEW
            exIP, exPort, exProto, exCnt := topDstTriple(top.flows)
            tops := topKDsts(top.flows, 3) // optional top-3
            shape := explainShape(top.fv)
            // recompute HBOS on the top vector for visibility
            topHBOS, topTau := 0.0, 0.0
            if a.hbos != nil {
                topHBOS = a.hbos.Score(log1pVec(top.fv.slice()))
                topTau  = a.hbos.Bound(0.99)
            }
            logAnomalyLine("DEBUG top_if=%.4f top_hbos=%.2f(τ=%.2f) top_src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d tops=%v shape=%v feats={PktsPerSec:%.1f,BytesPerSec:%.1f,MeanPkt:%.1f,UniqDstIPs:%.0f,UniqDstPorts:%.0f,TCPSYNRatio:%.2f,ICMPShare:%.2f}",
                top.score, topHBOS, topTau, top.src, ptr, asn, asnName, cc,
                exIP, exPort, exProto, exCnt, tops, shape,
                top.fv.PktsPerSec, top.fv.BytesPerSec, top.fv.MeanPktSize,
                top.fv.UniqDstIPs, top.fv.UniqDstPorts, top.fv.TCPSYNRatio, top.fv.ICMPShare)
        }

    // --- end add ---

	// periodic retrain
	if now.Sub(a.lastTrain) >= a.cfg.RetrainEvery {
		a.mu.Lock()
		b := a.baseline
		a.mu.Unlock()


                if len(b) >= 128 { // ensure enough samples
                        _ = a.detector.Train(b)
                        if a.hbos != nil { a.hbos.Train(b) }
                        if a.ehbos != nil { a.ehbos.Train(b) }
                        if wb, ok := a.detector.(interface{ Bound() float64 }); ok {

       switch {
       case a.hbos != nil && a.ehbos != nil:
           logAnomalyLine("TRAIN baseline=%d if_bound=%.4f hbos_tau99=%.2f ehbos_tau99=%.2f",
               len(b), wb.Bound(), a.hbos.Bound(0.99), a.ehbos.Bound(0.99))
       case a.hbos != nil:
           logAnomalyLine("TRAIN baseline=%d if_bound=%.4f hbos_tau99=%.2f",
               len(b), wb.Bound(), a.hbos.Bound(0.99))
       case a.ehbos != nil:
           logAnomalyLine("TRAIN baseline=%d if_bound=%.4f ehbos_tau99=%.2f",
               len(b), wb.Bound(), a.ehbos.Bound(0.99))
       default:
           logAnomalyLine("TRAIN baseline=%d if_bound=%.4f",
               len(b), wb.Bound())
       }

                        } else {
                                logAnomalyLine("TRAIN baseline=%d", len(b))
                        }


			a.lastTrain = now
		}
	}
a.afterTickPrintInteresting(now)

}





// ---- mean-based “interesting” printer to risk.log ----
// We compute mean of fused scores for this tick and print candidates >= mean*(1+P)
// If TopK>0, we limit to top-K by fused before printing.

type cand struct {
        src         string
        fused, ifs  float64
        hraw, hnorm float64
        ehr,  ehn   float64
        feat        featureVector
        flows       []Flow
        asn         uint32
        asnName     string
        cc, ptr     string
        exIP        string
        exPort      uint16
        exProto     string
        exCnt       int
        shape       []string
}

var candidates []cand

func meanFused(xs []cand) float64 {
        if len(xs) == 0 { return 0 }
        s := 0.0
        for _, c := range xs { s += c.fused }
        return s / float64(len(xs))
}

func (a *Anomaly) afterTickPrintInteresting(now time.Time) {
        if len(candidates) == 0 { return }
        // build a filtered slice without allowlisted ASNs
        filtered := candidates[:0]
        for _, c := range candidates {
            if a.isAllowedASN(c.asn) { continue }
            filtered = append(filtered, c)
        }
        if len(filtered) == 0 {
            candidates = candidates[:0]
            return
        }
        mu := meanFused(filtered)
        thr := mu * (1.0 + a.cfg.PrintAboveMeanPercent/100.0)

        // sort by fused desc
        sort.Slice(filtered, func(i, j int) bool { return filtered[i].fused > filtered[j].fused })

        limit := len(filtered)
        if a.cfg.TopK > 0 && a.cfg.TopK < limit {
                limit = a.cfg.TopK
        }
        printed := 0
        for i := 0; i < limit; i++ {
                c := filtered[i]
                if c.fused < thr {
                        break
                }
                // NOTE: rely on Go logger timestamp; no inner timestamp here.
                logRiskLine("[%s] RISK fused=%.4f if=%.4f hbos_norm=%.4f ehbos_norm=%.4f hbos_raw=%.2f mu=%.4f thr=%.4f src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d shape=%v feats=%v",
                        nowRFC3339(), c.fused, c.ifs, c.hnorm, c.ehn, c.hraw, mu, thr, c.src, c.ptr, c.asn, c.asnName, c.cc,
                        c.exIP, c.exPort, c.exProto, c.exCnt, c.shape, c.feat)
                printed++
        }
        // clear for next tick
        candidates = candidates[:0]
}

// -------- helpers (dst summarization & explanation) --------

// pick the most frequent (dst_ip, dst_port, proto) in the current window
func topDstTriple(flows []Flow) (ip string, port uint16, proto string, count int) {
    type key struct{ ip string; port uint16; proto string }
    m := map[key]int{}
    var best key
    for _, f := range flows {
        k := key{ip: f.DstIP, port: f.DstPort, proto: f.Proto}
        m[k]++
        if m[k] > count {
            count = m[k]
            best = k
        }
    }
    return best.ip, best.port, best.proto, count
}

// return the top-K destination tuples for richer context
func topKDsts(flows []Flow, k int) []string {
    type key struct{ ip string; port uint16; proto string }
    m := map[key]int{}
    for _, f := range flows {
        m[key{f.DstIP, f.DstPort, f.Proto}]++
    }
    type item struct{ k key; n int }
    arr := make([]item, 0, len(m))
    for kk, v := range m { arr = append(arr, item{kk, v}) }
    sort.Slice(arr, func(i, j int) bool { return arr[i].n > arr[j].n })
    if k > len(arr) { k = len(arr) }
    out := make([]string, 0, k)
    for i := 0; i < k; i++ {
        it := arr[i]
        out = append(out, fmt.Sprintf("%s:%d/%s x%d", it.k.ip, it.k.port, it.k.proto, it.n))
    }
    return out
}

// produce human-readable “shape” tags that hint why it was flagged
func explainShape(v featureVector) []string {
    var r []string
    if v.TCPSYNRatio >= 0.95 { r = append(r, "syn-heavy") }
    switch {
    case v.UniqDstIPs <= 1:
        r = append(r, "single-dst-ip")
    case v.UniqDstIPs >= 50:
        r = append(r, "wide-dst-sweep")
    }
    switch {
    case v.UniqDstPorts <= 1:
        r = append(r, "single-port")
    case v.UniqDstPorts >= 30:
        r = append(r, "port-scan")
    }
    if v.ICMPShare >= 0.30  { r = append(r, "icmp-heavy") }
    if v.PktsPerSec >= 500  { r = append(r, "high-pps") }
    if v.BytesPerSec >= 1e8 { r = append(r, "high-bps") } // ~100MB/s
    return r
}



// helper used above for HBOS normalization safety
func isFinite(x float64) bool {
    return !(x != x || x > 1e308 || x < -1e308)
}
