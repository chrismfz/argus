package alerter

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

// Global is set once in main.go after DB is ready.
// Every subsystem (BGP, detection, routewatch) calls alerter.Global.SendAsync(e).
var Global *Dispatcher

// Broadcast is the SSE channel. The SSE handler reads from it.
// Buffered to 128 — slow SSE clients don't block Send().
var Broadcast = make(chan FiredEvent, 128)

// Dispatcher fans events out to all matching contacts concurrently
// and records every attempt in the DB.
type Dispatcher struct {
	mu       sync.RWMutex
	db       *sql.DB
	contacts []Contact  // live copy reloaded via Reload()
	backends map[string]backendFactory
}

// backendFactory builds a Backend from a Contact's JSON config.
// Registered by each backend package via RegisterFactory.
type backendFactory func(c Contact) (Backend, error)

var factories = map[string]backendFactory{}

// RegisterFactory lets backend packages register themselves at init time.
// Called from each backend's init() so the dispatcher can build them.
func RegisterFactory(typ string, f backendFactory) {
	factories[typ] = f
}

// New creates a Dispatcher. Call Reload() to load contacts from DB.
func New(db *sql.DB) *Dispatcher {
	return &Dispatcher{
		db:       db,
		backends: factories,
	}
}

// Reload re-reads all enabled contacts from the DB and rebuilds backend instances.
// Safe to call at any time — uses a write lock.
func (d *Dispatcher) Reload() error {
	contacts, err := LoadContacts(d.db)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.contacts = contacts
	d.mu.Unlock()
	log.Printf("[alerter] reloaded: %d contacts", len(contacts))
	return nil
}

// Send delivers e to all matching contacts, writes to DB, pushes to SSE.
// Blocks until all deliveries complete. Use SendAsync for fire-and-forget.
func (d *Dispatcher) Send(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	d.mu.RLock()
	contacts := make([]Contact, len(d.contacts))
	copy(contacts, d.contacts)
	d.mu.RUnlock()

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		deliveries []DeliveryResult
	)

	for _, c := range contacts {
		if !c.Enabled {
			continue
		}
		if !severityMatches(c.MinSeverity, e.Severity) {
			mu.Lock()
			deliveries = append(deliveries, DeliveryResult{
				ContactID:   c.ID,
				ContactName: c.Name,
				ContactType: c.Type,
				Status:      "suppressed",
				AttemptedAt: time.Now().UTC(),
			})
			mu.Unlock()
			continue
		}
		if !sourceMatches(c.Sources, e.Source) {
			mu.Lock()
			deliveries = append(deliveries, DeliveryResult{
				ContactID:   c.ID,
				ContactName: c.Name,
				ContactType: c.Type,
				Status:      "suppressed",
				AttemptedAt: time.Now().UTC(),
			})
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(contact Contact) {
			defer wg.Done()
			result := d.deliver(ctx, contact, e, "sent")
			mu.Lock()
			deliveries = append(deliveries, result)
			mu.Unlock()
		}(c)
	}

	// Always add a log backend delivery record (the log backend is implicit)
	deliveries = append(deliveries, DeliveryResult{
		ContactID:   0,
		ContactName: "system log",
		ContactType: "log",
		Status:      "sent",
		AttemptedAt: time.Now().UTC(),
	})

	wg.Wait()

	// Persist to DB
	eventID, err := WriteEvent(d.db, e, deliveries)
	if err != nil {
		log.Printf("[alerter] db write failed: %v", err)
	}

	// Push to SSE broadcast channel (non-blocking)
	fired := FiredEvent{
		ID:         eventID,
		Event:      e,
		Deliveries: deliveries,
	}
	select {
	case Broadcast <- fired:
	default:
		log.Printf("[alerter] broadcast channel full, SSE clients may be slow")
	}
}

// SendAsync calls Send in a goroutine. Use this from subsystems.
func (d *Dispatcher) SendAsync(e Event) {
	go d.Send(context.Background(), e)
}

// SendTest sends a test event to a single contact and returns the result.
// Does NOT write to DB or broadcast SSE (it's a test, not a real alert).
func (d *Dispatcher) SendTest(ctx context.Context, contactID int64) (*DeliveryResult, error) {
	c, err := GetContact(d.db, contactID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}

	e := Event{
		Title:    "Argus test alert",
		Body:     "This is a test message from Argus. If you see this, the contact is configured correctly.",
		Severity: SeverityInfo,
		Source:   SourceTest,
		Tags:     map[string]string{"contact": c.Name},
		Time:     time.Now().UTC(),
	}

	result := d.deliver(ctx, *c, e, "test")

	// Write test to DB so it shows in the log
	_, _ = WriteEvent(d.db, e, []DeliveryResult{result})

	// Broadcast to SSE so it appears in the live feed
	fired := FiredEvent{Event: e, Deliveries: []DeliveryResult{result}}
	select {
	case Broadcast <- fired:
	default:
	}

	return &result, nil
}

// deliver builds the backend for a contact and calls Send.
func (d *Dispatcher) deliver(ctx context.Context, c Contact, e Event, okStatus string) DeliveryResult {
	result := DeliveryResult{
		ContactID:   c.ID,
		ContactName: c.Name,
		ContactType: c.Type,
		AttemptedAt: time.Now().UTC(),
	}

	factory, ok := factories[c.Type]
	if !ok {
		result.Status = "failed"
		result.Error = "unknown contact type: " + c.Type
		return result
	}

	backend, err := factory(c)
	if err != nil {
		result.Status = "failed"
		result.Error = "build backend: " + err.Error()
		return result
	}

	if err := backend.Send(ctx, e); err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		log.Printf("[alerter] %s contact %q failed: %v", c.Type, c.Name, err)
	} else {
		result.Status = okStatus
	}

	return result
}

// severityMatches returns true if the event severity >= contact min_severity
func severityMatches(minSeverity Severity, eventSeverity Severity) bool {
	return SeverityRank(eventSeverity) >= SeverityRank(minSeverity)
}

// sourceMatches returns true if sources="" (all) or source is in the list
func sourceMatches(sources string, eventSource Source) bool {
	if sources == "" {
		return true
	}
	for _, s := range strings.Split(sources, ",") {
		if strings.TrimSpace(s) == string(eventSource) {
			return true
		}
	}
	return false
}

// Snapshot returns a copy of the current contact list (for logging, etc.)
func (d *Dispatcher) Snapshot() []Contact {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Contact, len(d.contacts))
	copy(out, d.contacts)
	return out
}

// SSEMarshal returns the JSON-encoded FiredEvent for an SSE stream.
func SSEMarshal(fe FiredEvent) ([]byte, error) {
	return json.Marshal(fe)
}
