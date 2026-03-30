package logbackend

import (
	"context"
	"log"

	"argus/internal/alerter"
)

type LogBackend struct{}

func New() *LogBackend { return &LogBackend{} }

func (l *LogBackend) Name() string { return "log" }

func (l *LogBackend) Send(_ context.Context, e alerter.Event) error {
	log.Printf("[ALERT] [%s] [%s] %s — %s", e.Severity, e.Source, e.Title, e.Body)
	return nil
}
