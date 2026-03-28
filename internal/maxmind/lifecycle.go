package maxmind

import (
	"context"
	"log"
	"os"

	"argus/internal/config"
)

// Lifecycle owns the start/stop state of the MaxMind updater.
// Create once with NewLifecycle, then call ApplyConfig on every daemon tick
// after config is parsed. It is a no-op when nothing relevant has changed.
type Lifecycle struct {
	cancel  context.CancelFunc
	started bool
}

// NewLifecycle returns a ready-to-use Lifecycle.
func NewLifecycle() *Lifecycle {
	return &Lifecycle{}
}

// ApplyConfig starts, stops, or does nothing based on cfg.
// Safe to call on every tick — it only acts when the enabled state changes.
func (l *Lifecycle) ApplyConfig(ctx context.Context, cfg *config.MaxMindConfig) {
	// apply default dir
	if cfg.DBPath == "" {
		cfg.DBPath = "/var/lib/argus/maxmind"
	}

	_ = os.MkdirAll(cfg.DBPath, 0o755)
	_ = os.Chmod(cfg.DBPath, 0o755)

	switch {
	case cfg.Enabled && !l.started:
		upd := New(Config{
			Enabled:         cfg.Enabled,
			AccountID:       cfg.AccountID,
			LicenseKey:      cfg.LicenseKey,
			Editions:        cfg.Editions,
			Dir:             cfg.DBPath,
			CheckEvery:      cfg.CheckEvery,
			MinAgeBetweenDL: cfg.MinAge,
			HTTPTimeout:     cfg.HTTPTimeout,
		})
		c, cancel := context.WithCancel(ctx)
		l.cancel = cancel
		l.started = true
		go func() {
			if err := upd.Run(c, log.Printf); err != nil && c.Err() == nil {
				log.Printf("[maxmind] updater stopped: %v", err)
			}
		}()
		log.Printf("[maxmind] updater started (editions=%v dir=%s every=%s min_age=%s)",
			cfg.Editions, cfg.DBPath, cfg.CheckEvery, cfg.MinAge)

	case !cfg.Enabled && l.started:
		l.cancel()
		l.cancel = nil
		l.started = false
		log.Printf("[maxmind] updater stopped (disabled)")
	}
}

// Stop cleanly shuts down the updater. Call on daemon exit.
func (l *Lifecycle) Stop() {
	if l.started && l.cancel != nil {
		l.cancel()
		l.cancel = nil
		l.started = false
	}
}
