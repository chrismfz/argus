package detection

import (
	"context"
//	"math"
	"sync"
	"time"
)

type AnomalyConfig struct {
	Window        time.Duration // aggregation window (e.g., 60s)
	Interval      time.Duration // how often to score (e.g., 10s)
	Label         string        // "iforest_anomaly"
	MinScore      float64       // anomaly score threshold (0..1)
	LogOnly       bool          // true = never escalate

	// iForest training
	RetrainEvery  time.Duration // e.g., 5m
	BaselineMax   int           // cap baseline vectors (e.g., 20000)

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

	baseline [][]float64
	lastTrain time.Time
}

func NewAnomaly(cfg AnomalyConfig, det Detector, store DetectionStore) *Anomaly {
	if cfg.Window <= 0 { cfg.Window = 60 * time.Second }
	if cfg.Interval <= 0 { cfg.Interval = 10 * time.Second }
	if cfg.Label == "" { cfg.Label = "iforest_anomaly" }
	if cfg.RetrainEvery <= 0 { cfg.RetrainEvery = 5 * time.Minute }
	if cfg.BaselineMax <= 0 { cfg.BaselineMax = 20000 }
	if cfg.MinScore <= 0 { cfg.MinScore = 0.70 }

	return &Anomaly{
		bySrc:    make(map[string]*srcWindow),
		cfg:      cfg,
		detector: det,
		store:    store,
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
	t := time.NewTicker(a.cfg.Interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.tick()
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
		if label == 1 && score >= a.cfg.MinScore {
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


