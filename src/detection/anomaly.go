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
	// iForest training
	RetrainEvery  time.Duration // e.g., 5m
	BaselineMax   int           // cap baseline vectors (e.g., 20000)

	TopK          int            // optional: max anomalies to log per tick (0 = no cap)

	// optional blackhole escalation (later)
	BlackholeCount int
	BlackholeTime  interface{}

  // NEW: noise controls
  UseIFLabel     bool     // if false, ignore detector's label() and use thresholds only
  RequireHBOS    bool     // if true, require HBOS to exceed percentile bound too
  HBOSPercentile float64  // e.g., 0.99 or 0.995
  // Optional allowlist knobs (cheap, best-effort)
  AllowASNs      []uint32 // sources with these ASNs are ignored unless very strong


}

type Anomaly struct {
	mu        sync.Mutex
	bySrc     map[string]*srcWindow
	cfg       AnomalyConfig
	detector  Detector
        hbos      *HBOS
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
        if cfg.HBOSPercentile <= 0 { cfg.HBOSPercentile = 0.99 }
        // default: keep current behavior unless user opts out
        if !cfg.UseIFLabel { cfg.UseIFLabel = false } // explicit; zero value is false

	return &Anomaly{
		bySrc:    make(map[string]*srcWindow),
		cfg:      cfg,
		detector: det,
                hbos:     NewHBOS(15, 1e-6),
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

		label, score := a.detector.Score(vec)


                // parallel HBOS score (if trained)
                hbosScore := 0.0
                hbosTau := 0.0
                if a.hbos != nil {
                        hbosScore = a.hbos.Score(vec)
                        hbosTau   = a.hbos.Bound(a.cfg.HBOSPercentile)
                }


                if score > top.score {
                    top = scored{src: src, score: score, fv: feat, flows: local}
                }


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


//ORIGINAL COMMENTED FOR DEBUG//
//		if label == 1 && score >= a.cfg.MinScore {
// TEMP (for debug): fire if EITHER the label OR score threshold hits
//if label == 1 || score >= a.cfg.MinScore {

//BOUND METHOD//

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
        // (b) optionally AND-gate with HBOS outlier
        if fire && a.cfg.RequireHBOS && a.hbos != nil {
            if hbosScore < hbosTau {
                fire = false
            }
        }
        // (c) optional cheap allowlist by ASN (still lets very strong stuff pass if you wish)
        if fire && len(a.cfg.AllowASNs) > 0 && enrich.Global != nil && enrich.Global.Geo != nil {
            asn := enrich.Global.Geo.GetASNNumber(src)
            for _, allowed := range a.cfg.AllowASNs {
                if asn == allowed {
                    // suppress benign bot noise from trusted ASNs
                    fire = false
                    break
                }
            }
        }


        if fire {
			cnt, _ := a.store.IncrementCount(a.cfg.Label, src)

                        asn, asnName, cc, ptr := getEnrichLabels(src) // NEW
                        exIP, exPort, exProto, exCnt := topDstTriple(local)
                        shape := explainShape(feat)
            logAnomalyLine("[%s] ANOMALY label=%s if=%.4f hbos=%.2f(τ=%.2f) src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d shape=%v feats=%v count=%d",
                nowRFC3339(), a.cfg.Label, score, hbosScore, hbosTau, src, ptr, asn, asnName, cc,
                            exIP, exPort, exProto, exCnt, shape, feat, cnt)

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
				logAnomalyLine("[%s] ESCALATE blackhole src=%s count=%d", nowRFC3339(), src, cnt)
			}
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
            logAnomalyLine("[%s] DEBUG top_if=%.4f top_hbos=%.2f(τ=%.2f) top_src=%s PTR=%s ASN=AS%d (%s) CC=%s example_dst=%s:%d/%s x%d tops=%v shape=%v feats={PktsPerSec:%.1f,BytesPerSec:%.1f,MeanPkt:%.1f,UniqDstIPs:%.0f,UniqDstPorts:%.0f,TCPSYNRatio:%.2f,ICMPShare:%.2f}",
                nowRFC3339(), top.score, topHBOS, topTau, top.src, ptr, asn, asnName, cc,
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
                        if wb, ok := a.detector.(interface{ Bound() float64 }); ok {
                                if a.hbos != nil {
                                        logAnomalyLine("[%s] TRAIN baseline=%d if_bound=%.4f hbos_tau99=%.2f",
                                                nowRFC3339(), len(b), wb.Bound(), a.hbos.Bound(0.99))
                                } else {
                                        logAnomalyLine("[%s] TRAIN baseline=%d if_bound=%.4f",
                                                nowRFC3339(), len(b), wb.Bound())
                                }
                        } else {
                                logAnomalyLine("[%s] TRAIN baseline=%d", nowRFC3339(), len(b))
                        }


			a.lastTrain = now
		}
	}
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
