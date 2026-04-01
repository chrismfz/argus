package bgpmon

import (
	"database/sql"
	"fmt"

	"argus/internal/bgpstate"
)

// InitSchema creates the two bgpmon tables inside the shared detections.sqlite
// database. Safe to call on every startup — all statements are idempotent.
//
// Called from main.go immediately after the shared DB is opened, before
// bgpmon.New() is constructed.
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(`
		-- Current state snapshot — one row per session name, replaced on every poll.
		CREATE TABLE IF NOT EXISTS bgp_session_state (
			name            TEXT    PRIMARY KEY,
			comment         TEXT    NOT NULL DEFAULT '',
			remote_as       INTEGER NOT NULL DEFAULT 0,
			remote_as_name  TEXT    NOT NULL DEFAULT '',
			remote_address  TEXT    NOT NULL DEFAULT '',
			local_address   TEXT    NOT NULL DEFAULT '',
			afi             TEXT    NOT NULL DEFAULT '',
			state           TEXT    NOT NULL DEFAULT 'unknown',
			established     INTEGER NOT NULL DEFAULT 0,
			uptime_raw      TEXT    NOT NULL DEFAULT '',
			prefixes_rx     INTEGER NOT NULL DEFAULT 0,
			prefixes_tx     INTEGER NOT NULL DEFAULT 0,
			last_seen       INTEGER NOT NULL DEFAULT 0,
			connection_name TEXT    NOT NULL DEFAULT ''
		);

		-- Event log — append-only, never updated.
		CREATE TABLE IF NOT EXISTS bgp_session_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ts            INTEGER NOT NULL,
			session       TEXT    NOT NULL,
			remote_as     INTEGER NOT NULL DEFAULT 0,
			event         TEXT    NOT NULL,
			from_state    TEXT    NOT NULL DEFAULT '',
			to_state      TEXT    NOT NULL DEFAULT '',
			uptime_before TEXT    NOT NULL DEFAULT '',
			detail        TEXT    NOT NULL DEFAULT ''
		);

		CREATE INDEX IF NOT EXISTS idx_bgp_events_ts
			ON bgp_session_events(ts DESC);

		CREATE INDEX IF NOT EXISTS idx_bgp_events_session
			ON bgp_session_events(session, ts DESC);
	`)
	if err != nil {
		return fmt.Errorf("bgpmon InitSchema: %w", err)
	}
	return nil
}

// ── State table ───────────────────────────────────────────────────────────────

// UpsertSessionState writes the current state of one session to the DB.
// Uses INSERT OR REPLACE so stale rows for renamed sessions do not accumulate.
// Called on every poll cycle for each session returned by RouterOS.
func UpsertSessionState(db *sql.DB, s bgpstate.SessionStatus) error {
	_, err := db.Exec(`
		INSERT OR REPLACE INTO bgp_session_state
			(name, comment, remote_as, remote_as_name,
			 remote_address, local_address, afi,
			 state, established, uptime_raw,
			 prefixes_rx, prefixes_tx, last_seen, connection_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		s.Name, s.Comment, s.RemoteAS, s.RemoteASName,
		s.RemoteAddress, s.LocalAddress, s.AFI,
		s.State, boolToInt(s.Established), s.UptimeRaw,
		s.PrefixesRx, s.PrefixesTx, s.LastSeen, s.ConnectionName,
	)
	if err != nil {
		return fmt.Errorf("UpsertSessionState %q: %w", s.Name, err)
	}
	return nil
}

// ListSessionStates returns all rows from bgp_session_state ordered by name.
// Used by the /bgp/sessions handler to serve the current snapshot, and by
// ROUTEWATCH to query session health without going through the Monitor interface.
func ListSessionStates(db *sql.DB) ([]bgpstate.SessionStatus, error) {
	rows, err := db.Query(`
		SELECT name, comment, remote_as, remote_as_name,
		       remote_address, local_address, afi,
		       state, established, uptime_raw,
		       prefixes_rx, prefixes_tx, last_seen, connection_name
		FROM bgp_session_state
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("ListSessionStates: %w", err)
	}
	defer rows.Close()

	var out []bgpstate.SessionStatus
	for rows.Next() {
		var s bgpstate.SessionStatus
		var established int
		if err := rows.Scan(
			&s.Name, &s.Comment, &s.RemoteAS, &s.RemoteASName,
			&s.RemoteAddress, &s.LocalAddress, &s.AFI,
			&s.State, &established, &s.UptimeRaw,
			&s.PrefixesRx, &s.PrefixesTx, &s.LastSeen, &s.ConnectionName,
		); err != nil {
			return nil, fmt.Errorf("ListSessionStates scan: %w", err)
		}
		s.Established = established != 0
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── Event log ─────────────────────────────────────────────────────────────────

// InsertEvent appends one event to bgp_session_events and sets e.ID to the
// newly assigned row ID.
//
// Events are never updated or deleted — the log is intentionally append-only.
// Retention policy (if ever needed) can be implemented as a periodic DELETE
// WHERE ts < cutoff, separate from this function.
func InsertEvent(db *sql.DB, e *bgpstate.SessionEvent) error {
	row := db.QueryRow(`
		INSERT INTO bgp_session_events
			(ts, session, remote_as, event,
			 from_state, to_state, uptime_before, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`,
		e.Timestamp, e.Session, e.RemoteAS, string(e.Kind),
		e.FromState, e.ToState, e.UptimeBefore, e.Detail,
	)
	if err := row.Scan(&e.ID); err != nil {
		return fmt.Errorf("InsertEvent %q/%s: %w", e.Session, e.Kind, err)
	}
	return nil
}

// ListEvents returns recent events from bgp_session_events, newest first.
//
//   - limit: maximum rows to return (capped at 500 to protect the HTTP handler).
//     Pass 0 to use the default of 100.
//   - sessionFilter: if non-empty, only events for that session are returned.
//     Pass "" to return events across all sessions.
func ListEvents(db *sql.DB, limit int, sessionFilter string) ([]bgpstate.SessionEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	var (
		rows *sql.Rows
		err  error
	)

	if sessionFilter != "" {
		rows, err = db.Query(`
			SELECT id, ts, session, remote_as, event,
			       from_state, to_state, uptime_before, detail
			FROM bgp_session_events
			WHERE session = ?
			ORDER BY ts DESC
			LIMIT ?
		`, sessionFilter, limit)
	} else {
		rows, err = db.Query(`
			SELECT id, ts, session, remote_as, event,
			       from_state, to_state, uptime_before, detail
			FROM bgp_session_events
			ORDER BY ts DESC
			LIMIT ?
		`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("ListEvents: %w", err)
	}
	defer rows.Close()

	var out []bgpstate.SessionEvent
	for rows.Next() {
		var e bgpstate.SessionEvent
		var kind string
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.Session, &e.RemoteAS, &kind,
			&e.FromState, &e.ToState, &e.UptimeBefore, &e.Detail,
		); err != nil {
			return nil, fmt.Errorf("ListEvents scan: %w", err)
		}
		e.Kind = bgpstate.EventKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
