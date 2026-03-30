package alerter

import (
	"context"
	"time"
)

// Severity levels — contacts filter by min_severity
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Source identifies which subsystem fired the alert
type Source string

const (
	SourceBGP        Source = "bgp"
	SourceRouteWatch Source = "routewatch"
	SourceBlackhole  Source = "blackhole"
	SourceDetection  Source = "detection"
	SourceSystem     Source = "system"
	SourceTest       Source = "test"
)

// Event is what every subsystem sends. No Slack/SMTP knowledge here.
type Event struct {
	Title    string            `json:"title"`
	Body     string            `json:"body"`
	Severity Severity          `json:"severity"`
	Source   Source            `json:"source"`
	Tags     map[string]string `json:"tags,omitempty"` // "prefix", "peer", "asn", etc.
	Time     time.Time         `json:"time"`
}

// DeliveryResult records one contact's send attempt
type DeliveryResult struct {
	ContactID   int64     `json:"contact_id"`
	ContactName string    `json:"contact_name"`
	ContactType string    `json:"contact_type"`
	Status      string    `json:"status"` // sent | failed | suppressed | test
	AttemptedAt time.Time `json:"attempted_at"`
	Error       string    `json:"error,omitempty"`
}

// FiredEvent is what gets broadcast over SSE and stored in alert_events.
// It carries the event itself and all delivery outcomes in one payload.
type FiredEvent struct {
	ID         int64            `json:"id"`
	Event      Event            `json:"event"`
	Deliveries []DeliveryResult `json:"deliveries"`
}

// Backend is implemented by slack, smtp, log, etc.
type Backend interface {
	// Name identifies this backend type in logs
	Name() string
	// Send delivers the event. Returns an error if delivery failed.
	Send(ctx context.Context, e Event) error
}

// severityRank maps severity to int for comparison
func SeverityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	default:
		return 0
	}
}
