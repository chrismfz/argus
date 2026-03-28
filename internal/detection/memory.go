package detection

import (
    "log"
    "os"
    "sync"
    "time"
//    "argus/internal/enrich"
"context"
)

type riskState struct {
    Risk        float64   // EWMA(score)
    Debt        float64   // leaky bucket
    Flags5m     float64   // decaying spike counter
    Flags30m    float64
    ConsecHigh  int
    LastBucket  int       // for “state change” logging
    LastSeen    time.Time
}

type MemoryConfig struct {
    Interval time.Duration
    Alpha, Theta, TauRisk float64
    DebtDecayPerTick, DebtWarn float64
    SpikeThreshold float64
    Decay5m, Decay30m float64
    ConsecHighWarn int
    TTL time.Duration
    LogPath string
    TopKEnrich int
    LogStateChangesOnly bool
}

type MemoryLayer struct {
    mu   sync.RWMutex
    st   sync.Map // ip -> *riskState
    cfg  MemoryConfig
    lg   *log.Logger
    once sync.Once
}

func NewMemoryLayer(cfg MemoryConfig) *MemoryLayer {
    m := &MemoryLayer{cfg: cfg}
    return m
}

func (m *MemoryLayer) initLogger() {
    m.once.Do(func() {
        path := m.cfg.LogPath
        if path == "" { path = "risk.log" }
        f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil { log.Fatalf("open risk log: %v", err) }
        m.lg = log.New(f, "", log.Ldate|log.Ltime)
    })
}

func (m *MemoryLayer) Update(ip string, score float64, feats featureVector) (state *riskState, reasons []string, shouldLog bool) {
    m.initLogger()
    now := time.Now().UTC()

    val, _ := m.st.LoadOrStore(ip, &riskState{LastBucket: -1})
    s := val.(*riskState)

    // EWMA
    s.Risk = m.cfg.Alpha*score + (1.0-m.cfg.Alpha)*s.Risk

    // Debt: accumulate above-theta
    if score > m.cfg.Theta {
        s.Debt += (score - m.cfg.Theta)
    }
    // Decay per tick
    s.Debt -= m.cfg.DebtDecayPerTick
    if s.Debt < 0 { s.Debt = 0 }

    // Flags
    if score >= m.cfg.SpikeThreshold {
        s.Flags5m += 1.0
        s.Flags30m += 1.0
        s.ConsecHigh += 1
    } else {
        s.ConsecHigh = 0
    }

    // Exponential-like decays per tick
    s.Flags5m *= m.cfg.Decay5m
    s.Flags30m *= m.cfg.Decay30m

    // Reasons to consider logging
    if score >= 0.70 { reasons = append(reasons, "if>=0.70") }
    if s.Risk >= m.cfg.TauRisk { reasons = append(reasons, "risk>=tau") }
    if s.Debt >= m.cfg.DebtWarn { reasons = append(reasons, "debt>=warn") }
    if s.ConsecHigh >= m.cfg.ConsecHighWarn { reasons = append(reasons, "consec_high") }

    // Buckets for state change logging
    bucket := 0
    switch {
    case s.Risk >= 0.85: bucket = 3
    case s.Risk >= 0.70: bucket = 2
    case s.Risk >= 0.50: bucket = 1
    default:             bucket = 0
    }

    shouldLog = len(reasons) > 0
    if m.cfg.LogStateChangesOnly && !shouldLog && bucket == s.LastBucket {
        // do not log same state repeatedly
        s.LastSeen = now
        return s, nil, false
    }

    // If bucket changed upward, force a log
    if bucket > s.LastBucket {
        reasons = append(reasons, "bucket↑")
        shouldLog = true
    }

    s.LastBucket = bucket
    s.LastSeen = now
    return s, reasons, shouldLog
}

func (m *MemoryLayer) MaybeLog(ip string, score float64, feats featureVector, s *riskState, reasons []string,
    asn uint32, asnName, country, ptr string, model string) {

    // Hard gate: emit only when EWMA risk is above threshold (reduces noise)
    if s.Risk < m.cfg.TauRisk {
        return
    }
    if len(reasons) == 0 { return }
    m.initLogger()
    m.lg.Printf("[%s] ip=%s if=%.3f risk=%.3f debt=%.2f flags5m=%.1f flags30m=%.1f consec=%d reasons=%v",
        time.Now().UTC().Format(time.RFC3339), ip, score, s.Risk, s.Debt, s.Flags5m, s.Flags30m, s.ConsecHigh, reasons)
    m.lg.Printf("       PTR=%s ASN=AS%d (%s) CC=%s feats={pps:%.0f,bps:%.0f,uniq_ports:%.0f,uniq_ips:%.0f,syn:%.2f,icmp:%.2f} model=%s",
        ptr, asn, asnName, country, feats.PktsPerSec, feats.BytesPerSec, feats.UniqDstPorts, feats.UniqDstIPs, feats.TCPSYNRatio, feats.ICMPShare, model)
}



// StartGC periodically purges stale IP states older than TTL.
func (m *MemoryLayer) StartGC(ctx context.Context) {
    if m.cfg.TTL <= 0 || m.cfg.Interval <= 0 {
        return
    }
    ticker := time.NewTicker(m.cfg.Interval)
    go func() {
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                now := time.Now().UTC()
                m.st.Range(func(k, v any) bool {
                    s := v.(*riskState)
                    if now.Sub(s.LastSeen) > m.cfg.TTL {
                        m.st.Delete(k)
                    }
                    return true
                })
            }
        }
    }()
}
