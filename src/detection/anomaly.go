package detection

import (
	"context"
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
}

type Anomaly struct {
	mu        sync.Mutex
	bySrc     map[string]*srcWindow
	cfg       AnomalyConfig
	detector  Detector
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

	return &Anomaly{
		bySrc:    make(map[string]*srcWindow),
		cfg:      cfg,
		detector: det,
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

	type scored struct{ src string; score float64; fv featureVector }
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

   if score > top.score {
            top = scored{src: src, score: score, fv: feat}
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
		if label == 1 && score >= a.cfg.MinScore {
// TEMP (for debug): fire if EITHER the label OR score threshold hits
//if label == 1 || score >= a.cfg.MinScore {
			cnt, _ := a.store.IncrementCount(a.cfg.Label, src)

			logAnomalyLine("[%s] ANOMALY label=%s score=%.4f src=%s feats=%v count=%d",
				nowRFC3339(), a.cfg.Label, score, src, feat, cnt)



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
        logAnomalyLine("[%s] DEBUG top_score=%.4f top_src=%s feats={PktsPerSec:%.1f,BytesPerSec:%.1f,MeanPkt:%.1f,UniqDstIPs:%.0f,UniqDstPorts:%.0f,TCPSYNRatio:%.2f,ICMPShare:%.2f}",
            nowRFC3339(), top.score, top.src,
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
			logAnomalyLine("[%s] TRAIN baseline=%d", nowRFC3339(), len(b))
			a.lastTrain = now
		}
	}
}


