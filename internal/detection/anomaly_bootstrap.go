package detection

import (
    "context"
    "math"
    "log"
    "time"
    "github.com/fsnotify/fsnotify"
    "argus/internal/config"
)

type featureVector struct {
	PktsPerSec    float64
	BytesPerSec   float64
	MeanPktSize   float64
	UniqDstIPs    float64
	UniqDstPorts  float64
	TCPSYNRatio   float64
	ICMPShare     float64
}

func (v featureVector) slice() []float64 {
	return []float64{
		v.PktsPerSec, v.BytesPerSec, v.MeanPktSize,
		v.UniqDstIPs, v.UniqDstPorts, v.TCPSYNRatio, v.ICMPShare,
	}
}

func log1pVec(x []float64) []float64 {
	out := make([]float64, len(x))
	for i, v := range x {
		if v < 0 {
			out[i] = -math.Log1p(-v)
		} else {
			out[i] = math.Log1p(v)
		}
	}
	return out
}


// startAnomalyStack wires:
//   - Memory layer (EWMA/debt risk)
// ---- Anomaly (iForest + HBOS + eHBOS fusion) ----
//   - fsnotify hot-reloads from the same config file
//
// It also binds the anomaly to the detection engine.
func StartAnomalyStack(
    ctx context.Context,
    cfg *config.Config,
    eng *Engine,
    store DetectionStore,
    configPath string,
) (*Anomaly, *MemoryLayer) {

    var mem *MemoryLayer

    // ---- Memory layer (optional) ----
    if cfg.Detection.Memory.Enabled {
        mivl, _ := time.ParseDuration(cfg.Detection.Memory.Interval)
        mttl, _ := time.ParseDuration(cfg.Detection.Memory.TTL)

	memCfg := MemoryConfig{
            Interval:            mivl,
            Alpha:               cfg.Detection.Memory.Alpha,
            Theta:               cfg.Detection.Memory.Theta,
            TauRisk:             cfg.Detection.Memory.TauRisk,
            DebtDecayPerTick:    cfg.Detection.Memory.Debt.DecayPerTick,
            DebtWarn:            cfg.Detection.Memory.Debt.WarnThreshold,
            SpikeThreshold:      cfg.Detection.Memory.Flags.SpikeThreshold,
            Decay5m:             cfg.Detection.Memory.Flags.Decay5m,
            Decay30m:            cfg.Detection.Memory.Flags.Decay30m,
            ConsecHighWarn:      cfg.Detection.Memory.Flags.ConsecHighWarn,
            TTL:                 mttl,
            LogPath:             cfg.Detection.Memory.LogPath,
            TopKEnrich:          cfg.Detection.Memory.TopKEnrich,
            LogStateChangesOnly: cfg.Detection.Memory.LogStateChangesOnly,
        }
	mem = NewMemoryLayer(memCfg)
        mem.StartGC(ctx)
    }

    // ---- Anomaly (iForest + HBOS) ----
    win, _  := time.ParseDuration(cfg.Detection.Anomaly.Window)
    ivl, _  := time.ParseDuration(cfg.Detection.Anomaly.Interval)
    retr, _ := time.ParseDuration(cfg.Detection.Anomaly.RetrainEvery)

    anomCfg := AnomalyConfig{
        Window:       win,
        Interval:     ivl,
        Label:        cfg.Detection.Anomaly.Label,
        MinScore:     cfg.Detection.Anomaly.MinScore,
        LogOnly:      cfg.Detection.Anomaly.LogOnly,
        Debug:        cfg.Detection.Anomaly.Debug,
        RetrainEvery: retr,
        BaselineMax:  cfg.Detection.Anomaly.BaselineMax,
        TopK:         cfg.Detection.Anomaly.TopK,
        // HBOS gating / fusion / mean printer / allowlist
        RequireHBOSPercentile: cfg.Detection.Anomaly.RequireHBOSPercentile,
        RequireEHBOSPercentile: cfg.Detection.Anomaly.RequireEHBOSPercentile,
        Weights: struct {
            IForest float64
            HBOS    float64
            EHBOS   float64
        }{
            IForest: cfg.Detection.Anomaly.Weights.IForest,
            HBOS:    cfg.Detection.Anomaly.Weights.HBOS,
            EHBOS:   cfg.Detection.Anomaly.Weights.EHBOS,
        },
        PrintAboveMeanPercent: cfg.Detection.Anomaly.PrintAboveMeanPercent,
        AllowASNs:             cfg.Detection.Anomaly.AllowASNs,
    }

    trees := cfg.Detection.Anomaly.Trees
    sampleSize := cfg.Detection.Anomaly.SampleSize
    contamination := cfg.Detection.Anomaly.Contamination
    if trees <= 0 { trees = 100 }
    if sampleSize <= 0 { sampleSize = 256 }
    if contamination <= 0 { contamination = 0.01 }

    det := NewIForestDetector(trees, sampleSize, contamination)
    anom := NewAnomaly(anomCfg, det, store)

    // Respect YAML eHBOS params (bins/eps/subspaces/size/agg)
    {
        eb := cfg.Detection.Anomaly.EHBOS
        bins := eb.Bins
        eps  := eb.Eps
        subs := eb.Subspaces
        size := eb.Size
        agg  := eb.Agg
        if bins <= 0 { bins = 12 }
        if eps  <= 0 { eps  = 1e-6 }
        if subs <= 0 { subs = 12 }
        if size <= 0 { size = 3 }
        if agg != "max" && agg != "mean" { agg = "max" }
        // Our feature space length is 7 (PktsPerSec, BytesPerSec, MeanPktSize, UniqDstIPs, UniqDstPorts, TCPSYNRatio, ICMPShare)
        anom.ehbos = NewEHBOS(bins, eps, subs, size, agg, 7)


        // --- Print eHBOS + fusion/gate config on startup ---
        log.Printf("[CFG] anomaly: require_hbos_percentile=%.3f require_ehbos_percentile=%.3f weights={iforest:%.2f,ehbos:%.2f,hbos:%.2f} print_above_mean_percent=%v allow_asns=%v",
            anomCfg.RequireHBOSPercentile, anomCfg.RequireEHBOSPercentile,
            anomCfg.Weights.IForest, anomCfg.Weights.EHBOS, anomCfg.Weights.HBOS,
            anomCfg.PrintAboveMeanPercent, anomCfg.AllowASNs)
        log.Printf("[CFG] anomaly.ehbos: bins=%d eps=%g subspaces=%d size=%d agg=%s",
            bins, eps, subs, size, agg)

    }


    if mem != nil {
        anom.SetMemory(mem)
    }
    eng.SetAnomaly(anom)
    anom.Start(ctx)

    // ---- Hot-reload watcher ----
    go func() {
        watcher, err := fsnotify.NewWatcher()
        if err != nil {
            log.Printf("[WARN] fsnotify init failed: %v", err)
            return
        }
        defer watcher.Close()

        if err := watcher.Add(configPath); err != nil {
            log.Printf("[WARN] fsnotify add failed: %v", err)
            return
        }

        treesCur, sampleCur, contamCur := trees, sampleSize, contamination

        for {
            select {
            case <-ctx.Done():
                return
            case ev := <-watcher.Events:
                if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
                    continue
                }
                time.Sleep(200 * time.Millisecond) // debounce

                nc, err := config.LoadConfig(configPath)
                if err != nil {
                    log.Printf("[WARN] reload config failed: %v", err)
                    continue
                }
                config.AppConfig = nc

                if !(nc.Detection.Enabled && nc.Detection.Anomaly.Enabled) {
                    continue
                }

                nwin, _  := time.ParseDuration(nc.Detection.Anomaly.Window)
                nivl, _  := time.ParseDuration(nc.Detection.Anomaly.Interval)
                nretr, _ := time.ParseDuration(nc.Detection.Anomaly.RetrainEvery)

                nextCfg := AnomalyConfig{
                    Window:       nwin,
                    Interval:     nivl,
                    Label:        nc.Detection.Anomaly.Label,
                    MinScore:     nc.Detection.Anomaly.MinScore,
                    LogOnly:      nc.Detection.Anomaly.LogOnly,
                    Debug:        nc.Detection.Anomaly.Debug,
                    RetrainEvery: nretr,
                    BaselineMax:  nc.Detection.Anomaly.BaselineMax,
                    TopK:         nc.Detection.Anomaly.TopK,
                    RequireHBOSPercentile:  nc.Detection.Anomaly.RequireHBOSPercentile,
                    RequireEHBOSPercentile: nc.Detection.Anomaly.RequireEHBOSPercentile,
                    Weights: struct {
                        IForest float64
                        HBOS    float64
                        EHBOS   float64
                    }{
                        IForest: nc.Detection.Anomaly.Weights.IForest,
                        HBOS:    nc.Detection.Anomaly.Weights.HBOS,
                        EHBOS:   nc.Detection.Anomaly.Weights.EHBOS,
                    },
                    PrintAboveMeanPercent: nc.Detection.Anomaly.PrintAboveMeanPercent,
                    AllowASNs:             nc.Detection.Anomaly.AllowASNs,
                }
                anom.UpdateConfig(nextCfg)


                // Also respect YAML eHBOS params on hot-reload
                {
                    eb := nc.Detection.Anomaly.EHBOS
                    bins := eb.Bins
                    eps  := eb.Eps
                    subs := eb.Subspaces
                    size := eb.Size
                    agg  := eb.Agg
                    if bins <= 0 { bins = 12 }
                    if eps  <= 0 { eps  = 1e-6 }
                    if subs <= 0 { subs = 12 }
                    if size <= 0 { size = 3 }
                    if agg != "max" && agg != "mean" { agg = "max" }
                    anom.ehbos = NewEHBOS(bins, eps, subs, size, agg, 7)
                    // --- Print eHBOS + fusion/gate config on reload ---
                    log.Printf("[CFG] anomaly: require_hbos_percentile=%.3f require_ehbos_percentile=%.3f weights={iforest:%.2f,ehbos:%.2f,hbos:%.2f} print_above_mean_percent=%v allow_asns=%v",
                        nextCfg.RequireHBOSPercentile, nextCfg.RequireEHBOSPercentile,
                        nextCfg.Weights.IForest, nextCfg.Weights.EHBOS, nextCfg.Weights.HBOS,
                        nextCfg.PrintAboveMeanPercent, nextCfg.AllowASNs)
                    log.Printf("[CFG] anomaly.ehbos: bins=%d eps=%g subspaces=%d size=%d agg=%s",
                        bins, eps, subs, size, agg)

                }


                nTrees := nc.Detection.Anomaly.Trees
                nSample := nc.Detection.Anomaly.SampleSize
                nContam := nc.Detection.Anomaly.Contamination
                if nTrees <= 0 { nTrees = 100 }
                if nSample <= 0 { nSample = 256 }
                if nContam <= 0 { nContam = 0.01 }

                if nTrees != treesCur || nSample != sampleCur || nContam != contamCur {
                    anom.RebuildDetector(nTrees, nSample, nContam)
                    treesCur, sampleCur, contamCur = nTrees, nSample, nContam
                    log.Printf("[ANOMALY] detector rebuilt (trees=%d sample=%d contam=%.3f)", nTrees, nSample, nContam)
                }

                // Optional: recreate memory layer on reload
                if nc.Detection.Memory.Enabled {
                    nmivl, _ := time.ParseDuration(nc.Detection.Memory.Interval)
                    nmttl, _ := time.ParseDuration(nc.Detection.Memory.TTL)
                    nmemCfg := MemoryConfig{
                        Interval:            nmivl,
                        Alpha:               nc.Detection.Memory.Alpha,
                        Theta:               nc.Detection.Memory.Theta,
                        TauRisk:             nc.Detection.Memory.TauRisk,
                        DebtDecayPerTick:    nc.Detection.Memory.Debt.DecayPerTick,
                        DebtWarn:            nc.Detection.Memory.Debt.WarnThreshold,
                        SpikeThreshold:      nc.Detection.Memory.Flags.SpikeThreshold,
                        Decay5m:             nc.Detection.Memory.Flags.Decay5m,
                        Decay30m:            nc.Detection.Memory.Flags.Decay30m,
                        ConsecHighWarn:      nc.Detection.Memory.Flags.ConsecHighWarn,
                        TTL:                 nmttl,
                        LogPath:             nc.Detection.Memory.LogPath,
                        TopKEnrich:          nc.Detection.Memory.TopKEnrich,
                        LogStateChangesOnly: nc.Detection.Memory.LogStateChangesOnly,
                    }
                    mem = NewMemoryLayer(nmemCfg)
                    mem.StartGC(ctx)
                    anom.SetMemory(mem)
                    log.Printf("[MEMORY] reloaded cfg: interval=%s alpha=%.2f theta=%.2f tau=%.2f",
                        nmemCfg.Interval, nmemCfg.Alpha, nmemCfg.Theta, nmemCfg.TauRisk)
                }
            case err := <-watcher.Errors:
                log.Printf("[WARN] fsnotify error: %v", err)
            }
        }
    }()

    return anom, mem
}
