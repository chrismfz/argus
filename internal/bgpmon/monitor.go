package bgpmon

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"argus/internal/alerter"
	"argus/internal/bgpstate"
	"argus/internal/routeros"
)

// Monitor polls the RouterOS REST API every 30 seconds, maintains in-memory
// session state, runs the state machine, and fires alerts through the alerter
// dispatcher. It implements bgpstate.Monitor.
//
// All exported methods (Sessions, SessionByName, Reachable, LastPoll) are safe
// for concurrent use. The internal poll loop runs in a single goroutine so the
// state machine maps (prevState, prevUptime, downSince) need no mutex.
type Monitor struct {
	db       *sql.DB
	ros      *routeros.Client
	al       *alerter.Dispatcher // may be nil — alerts silently dropped
	geo      bgpstate.GeoLookup  // may be nil — ASN names stay empty
	interval time.Duration

	// Protected by mu — read by HTTP handlers, written only by poll().
	mu           sync.RWMutex
	current      []bgpstate.SessionStatus
	rosReachable bool
	lastPoll     int64 // unix timestamp

	// State machine memory — only accessed inside poll() (single goroutine).
	prevState     map[string]string        // session name → last state string
	prevUptime    map[string]time.Duration // session name → last parsed uptime
	prevUptimeRaw map[string]string        // session name → last raw uptime string
	downSince     map[string]time.Time     // session name → time it went down

	// Connection enrichment — loaded once at startup, read-only thereafter.
	connComments map[string]string // connection name → human comment e.g. "GR-IX"
}

// New creates a Monitor. al and geo may both be nil — the monitor degrades
// gracefully (no alerts sent, ASN names stay empty).
//
// main.go wiring:
//
//	mon := bgpmon.New(db, rosClient, alerter.Global, geo)
//	go mon.Run(ctx)
//	api.BGPMon = mon  // typed as bgpstate.Monitor
func New(db *sql.DB, ros *routeros.Client, al *alerter.Dispatcher, geo bgpstate.GeoLookup) *Monitor {
	return &Monitor{
		db:            db,
		ros:           ros,
		al:            al,
		geo:           geo,
		interval:      30 * time.Second,
		rosReachable:  true, // optimistic — corrected on first poll failure
		prevState:     make(map[string]string),
		prevUptime:    make(map[string]time.Duration),
		prevUptimeRaw: make(map[string]string),
		downSince:     make(map[string]time.Time),
		connComments:  make(map[string]string),
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

// Run starts the polling loop and blocks until ctx is cancelled.
// Call as a goroutine: go mon.Run(ctx).
func (m *Monitor) Run(ctx context.Context) {
	log.Printf("[bgpmon] session monitor started (interval=%s)", m.interval)

	// Enrich connection comments once at startup.
	// Non-fatal if it fails — sessions will still work without human labels.
	m.loadConnectionComments(ctx)

	// First poll immediately so the dashboard has data before the first tick.
	m.poll(ctx)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.poll(ctx)
		case <-ctx.Done():
			log.Println("[bgpmon] monitor stopped")
			return
		}
	}
}

// ── Poll cycle ────────────────────────────────────────────────────────────────

// poll runs a single poll cycle: fetch sessions from RouterOS, run the state
// machine for each session, write state to DB, update in-memory snapshot.
func (m *Monitor) poll(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	sessions, err := m.ros.ListBGPSessions(pctx)
	if err != nil {
		m.handleRESTFailure(err)
		return
	}

	// RouterOS came back after being unreachable.
	m.mu.RLock()
	wasUnreachable := !m.rosReachable
	m.mu.RUnlock()
	if wasUnreachable {
		m.handleRESTRecovery()
	}

	now := time.Now().Unix()
	newCurrent := make([]bgpstate.SessionStatus, 0, len(sessions))

	for _, sess := range sessions {
		status := m.toStatus(sess, now)
		uptime := parseUptimeRaw(sess.UptimeRaw)

		// State machine: determine transition, fire events + alerts.
		m.runStateMachine(status, uptime)

		// Persist state (only when REST is reachable).
		if dbErr := UpsertSessionState(m.db, status); dbErr != nil {
			log.Printf("[bgpmon] upsert state %q: %v", status.Name, dbErr)
		}

		// Update state machine memory for next cycle.
		m.prevState[status.Name] = status.State
		if status.Established {
			m.prevUptime[status.Name] = uptime
			m.prevUptimeRaw[status.Name] = status.UptimeRaw
		}

		newCurrent = append(newCurrent, status)
	}

	m.mu.Lock()
	m.current = newCurrent
	m.rosReachable = true
	m.lastPoll = now
	m.mu.Unlock()

	log.Printf("[bgpmon] polled %d sessions", len(sessions))
}

// ── State machine ─────────────────────────────────────────────────────────────

// runStateMachine evaluates one session's state transition and fires the
// appropriate event + alert. It does NOT update prevState — poll() does that
// after calling this function so prevState always reflects the previous cycle.
func (m *Monitor) runStateMachine(status bgpstate.SessionStatus, uptime time.Duration) {
	prev, seen := m.prevState[status.Name]
	now := time.Now().Unix()

	if !seen {
		// First time we see this session during this run.
		if status.Established {
			// Record it as established — useful baseline in the event log.
			ev := &bgpstate.SessionEvent{
				Timestamp: now,
				Session:   status.Name,
				RemoteAS:  status.RemoteAS,
				Kind:      bgpstate.EventEstablished,
				ToState:   status.State,
				Detail:    "first seen",
			}
			m.fireEvent(ev)
			m.sendSessionAlert(bgpstate.EventEstablished, status, "")
		}
		// First seen as down: silent. We don't know how long it has been down,
		// so an alert with no context would be misleading.
		return
	}

	wasEstablished := prev == "established"
	isEstablished := status.Established

	switch {

	case !wasEstablished && isEstablished:
		// ── Recovered ──────────────────────────────────────────────────────────
		var downFor string
		if t, ok := m.downSince[status.Name]; ok {
			downFor = formatDuration(time.Since(t))
			delete(m.downSince, status.Name)
		}
		ev := &bgpstate.SessionEvent{
			Timestamp: now,
			Session:   status.Name,
			RemoteAS:  status.RemoteAS,
			Kind:      bgpstate.EventRecovered,
			FromState: prev,
			ToState:   status.State,
			Detail:    downFor,
		}
		m.fireEvent(ev)
		m.sendSessionAlert(bgpstate.EventRecovered, status, downFor)

	case wasEstablished && !isEstablished:
		// ── Went down ──────────────────────────────────────────────────────────
		prevRaw := m.prevUptimeRaw[status.Name]
		m.downSince[status.Name] = time.Now()
		ev := &bgpstate.SessionEvent{
			Timestamp:    now,
			Session:      status.Name,
			RemoteAS:     status.RemoteAS,
			Kind:         bgpstate.EventDown,
			FromState:    prev,
			ToState:      status.State,
			UptimeBefore: prevRaw,
		}
		m.fireEvent(ev)
		m.sendSessionAlert(bgpstate.EventDown, status, prevRaw)

	case wasEstablished && isEstablished:
		// ── Possible flap: check if uptime reset ───────────────────────────────
		// A genuine flap: previous uptime was meaningful (>= 30s) and current
		// uptime is less than half the previous value. This guards against minor
		// clock/formatting jitter on short-lived sessions.
		prevUp := m.prevUptime[status.Name]
		if prevUp >= 30*time.Second && uptime < prevUp/2 {
			prevRaw := m.prevUptimeRaw[status.Name]
			ev := &bgpstate.SessionEvent{
				Timestamp:    now,
				Session:      status.Name,
				RemoteAS:     status.RemoteAS,
				Kind:         bgpstate.EventFlap,
				FromState:    "established",
				ToState:      "established",
				UptimeBefore: prevRaw,
				Detail:       fmt.Sprintf("uptime reset from %s to %s", prevRaw, status.UptimeRaw),
			}
			m.fireEvent(ev)
			m.sendSessionAlert(bgpstate.EventFlap, status, prevRaw)
		}
	}
}

// ── REST failure / recovery ───────────────────────────────────────────────────

func (m *Monitor) handleRESTFailure(err error) {
	m.mu.Lock()
	wasReachable := m.rosReachable
	m.rosReachable = false
	m.lastPoll = time.Now().Unix()
	// Mark all in-memory sessions as unknown. Do NOT write to the state DB —
	// the last known good state is more useful than a page of "unknown" rows.
	for i := range m.current {
		m.current[i].State = "unknown"
		m.current[i].Established = false
	}
	m.mu.Unlock()

	if wasReachable {
		// Fire the alert exactly once per outage.
		ev := &bgpstate.SessionEvent{
			Timestamp: time.Now().Unix(),
			Session:   "_routeros",
			Kind:      bgpstate.EventUnreachable,
			Detail:    err.Error(),
		}
		m.fireEvent(ev)
		if m.al != nil {
			m.al.SendAsync(alerter.Event{
				Title:    "🔴 RouterOS REST unreachable — all session states unknown",
				Body:     err.Error(),
				Severity: alerter.SeverityCritical,
				Source:   alerter.SourceBGP,
				Tags:     map[string]string{"component": "routeros"},
				Time:     time.Now().UTC(),
			})
		}
	}
	log.Printf("[bgpmon] RouterOS REST unreachable: %v", err)
}

func (m *Monitor) handleRESTRecovery() {
	ev := &bgpstate.SessionEvent{
		Timestamp: time.Now().Unix(),
		Session:   "_routeros",
		Kind:      bgpstate.EventRESTRecovered,
		Detail:    "REST API reachable again",
	}
	m.fireEvent(ev)
	if m.al != nil {
		m.al.SendAsync(alerter.Event{
			Title:    "🟢 RouterOS REST recovered",
			Severity: alerter.SeverityInfo,
			Source:   alerter.SourceBGP,
			Tags:     map[string]string{"component": "routeros"},
			Time:     time.Now().UTC(),
		})
	}
	log.Println("[bgpmon] RouterOS REST recovered")
}

// ── Alert helpers ─────────────────────────────────────────────────────────────

// sendSessionAlert formats and dispatches an alert for a single session event.
// extra is context-dependent: uptime string for DOWN/FLAP, duration string for RECOVERED.
func (m *Monitor) sendSessionAlert(kind bgpstate.EventKind, s bgpstate.SessionStatus, extra string) {
	if m.al == nil {
		return
	}

	peer := peerLabel(s)
	var title, body string
	var sev alerter.Severity

	switch kind {
	case bgpstate.EventDown:
		title = "🔴 BGP DOWN: " + s.Name
		body = fmt.Sprintf("%s — %s", peer, s.Name)
		if extra != "" {
			body += " — was up " + extra
		}
		sev = alerter.SeverityCritical

	case bgpstate.EventRecovered:
		title = "🟢 BGP UP: " + s.Name
		body = fmt.Sprintf("%s — %s", peer, s.Name)
		if extra != "" {
			body += " — recovered after " + extra
		}
		sev = alerter.SeverityInfo

	case bgpstate.EventFlap:
		title = "⚠️ BGP FLAP: " + s.Name
		body = fmt.Sprintf("%s — %s", peer, s.Name)
		if extra != "" {
			body += " — uptime reset (was " + extra + ")"
		}
		sev = alerter.SeverityWarning

	case bgpstate.EventEstablished:
		title = "🟢 BGP ESTABLISHED: " + s.Name
		body = fmt.Sprintf("%s — %s", peer, s.Name)
		sev = alerter.SeverityInfo

	default:
		return
	}

	m.al.SendAsync(alerter.Event{
		Title:    title,
		Body:     body,
		Severity: sev,
		Source:   alerter.SourceBGP,
		Tags: map[string]string{
			"session": s.Name,
			"asn":     fmt.Sprintf("%d", s.RemoteAS),
			"afi":     s.AFI,
			"comment": s.Comment,
		},
		Time: time.Now().UTC(),
	})
}

// fireEvent inserts a SessionEvent to the DB and logs it.
// Continues on DB error — alerting should never block on a store failure.
func (m *Monitor) fireEvent(ev *bgpstate.SessionEvent) {
	if err := InsertEvent(m.db, ev); err != nil {
		log.Printf("[bgpmon] InsertEvent failed: %v", err)
		return
	}
	log.Printf("[bgpmon] event #%d: %s → %s", ev.ID, ev.Session, ev.Kind)
}

// ── bgpstate.Monitor interface ────────────────────────────────────────────────

// Sessions returns a snapshot of the current session state.
// Safe for concurrent use.
func (m *Monitor) Sessions() []bgpstate.SessionStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]bgpstate.SessionStatus, len(m.current))
	copy(out, m.current)
	return out
}

// SessionByName returns the current state of a single session by name.
// Returns (zero, false) if not found.
func (m *Monitor) SessionByName(name string) (bgpstate.SessionStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.current {
		if s.Name == name {
			return s, true
		}
	}
	return bgpstate.SessionStatus{}, false
}

// Reachable reports whether the RouterOS REST API was reachable on the last poll.
func (m *Monitor) Reachable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rosReachable
}

// LastPoll returns the unix timestamp of the most recent completed poll cycle.
func (m *Monitor) LastPoll() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPoll
}

// ── Conversion ────────────────────────────────────────────────────────────────

// toStatus converts a RouterOS BGPSession to a bgpstate.SessionStatus,
// enriching with MaxMind ASN name and connection comment where available.
// Note: PrefixesTx is not populated — RouterOS session API does not expose
// outbound prefix counts. Use the Advertisements tab for per-peer detail.
func (m *Monitor) toStatus(sess routeros.BGPSession, now int64) bgpstate.SessionStatus {
	asnName := ""
	if m.geo != nil && sess.RemoteAddress != "" {
		asnName = m.geo.GetASNName(sess.RemoteAddress)
	}

	comment := m.connComments[sess.ConnectionName]

	return bgpstate.SessionStatus{
		Name:           sess.Name,
		Comment:        comment,
		RemoteAS:       sess.RemoteAS,
		RemoteASName:   asnName,
		RemoteAddress:  sess.RemoteAddress,
		LocalAddress:   sess.LocalAddress,
		AFI:            afiFromSession(sess.Name, sess.RemoteAddress),
		State:          string(sess.State),
		Established:    sess.Established,
		UptimeRaw:      sess.UptimeRaw,
		PrefixesRx:     sess.PrefixesReceived,
		PrefixesTx:     0,
		LastSeen:       now,
		ConnectionName: sess.ConnectionName,
	}
}

// loadConnectionComments fetches /routing/bgp/connection once at startup and
// builds the connComments map (connection name → human comment).
// Non-fatal — logs a warning and leaves the map empty if it fails.
func (m *Monitor) loadConnectionComments(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	peers, err := m.ros.ListBGPPeers(pctx)
	if err != nil {
		log.Printf("[bgpmon] could not load connection comments: %v", err)
		return
	}
	for _, p := range peers {
		if p.Comment != "" {
			m.connComments[p.Name] = p.Comment
		}
	}
	log.Printf("[bgpmon] loaded comments for %d connections", len(m.connComments))
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

// afiFromSession derives "ip" or "ipv6" from the peer's remote address (most
// reliable) or falls back to name heuristics (for sessions not yet established).
func afiFromSession(name, remoteAddr string) string {
	if strings.Contains(remoteAddr, ":") {
		return "ipv6"
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "ipv6") || strings.Contains(lower, "-v6") {
		return "ipv6"
	}
	return "ip"
}

// peerLabel formats the peer identity for alert messages.
// "AS50745 (GR-IX Route Servers)" or "AS50745" if no name available.
func peerLabel(s bgpstate.SessionStatus) string {
	if s.RemoteASName != "" {
		return fmt.Sprintf("AS%d (%s)", s.RemoteAS, s.RemoteASName)
	}
	return fmt.Sprintf("AS%d", s.RemoteAS)
}

// parseUptimeRaw converts a RouterOS uptime string ("2w6d13h") to time.Duration.
// Returns 0 for empty or unparseable input. Mirrors routeros.parseROSUptime
// without importing the unexported function.
func parseUptimeRaw(s string) time.Duration {
	if s == "" {
		return 0
	}
	units := map[byte]time.Duration{
		'w': 7 * 24 * time.Hour,
		'd': 24 * time.Hour,
		'h': time.Hour,
		'm': time.Minute,
		's': time.Second,
	}
	var total time.Duration
	var num int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			num = num*10 + int(c-'0')
		} else if mul, ok := units[c]; ok {
			total += time.Duration(num) * mul
			num = 0
		}
	}
	return total
}

// formatDuration converts a duration to a human-readable string like "4m32s",
// "1h15m", or "3d2h" for use in alert messages.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		mins := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh%dm", h, mins)
	}
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hrs)
}
