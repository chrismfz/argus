package alerter

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Contact is one configured destination (a Slack hook, an SMTP target, etc.)
type Contact struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`        // slack | smtp | log
	Enabled     bool      `json:"enabled"`
	Config      string    `json:"config"`      // JSON blob, type-specific
	MinSeverity Severity  `json:"min_severity"`
	Sources     string    `json:"sources"`     // "" = all, or "bgp,routewatch,detection"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SlackConfig is the JSON stored in Contact.Config for type="slack"
type SlackConfig struct {
	Webhook string `json:"webhook"`
}

// SMTPConfig is the JSON stored in Contact.Config for type="smtp"
type SMTPConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	TLS      bool     `json:"tls"`
}

// InitSchema creates all three tables if they don't exist.
// Safe to call on every startup.
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS alert_contacts (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL,
			type         TEXT NOT NULL,
			enabled      INTEGER NOT NULL DEFAULT 1,
			config       TEXT NOT NULL DEFAULT '{}',
			min_severity TEXT NOT NULL DEFAULT 'info',
			sources      TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL,
			updated_at   TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS alert_events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts         TEXT NOT NULL,
			source     TEXT NOT NULL,
			severity   TEXT NOT NULL,
			title      TEXT NOT NULL,
			body       TEXT,
			tags       TEXT,
			fired_at   TEXT NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_alert_events_fired_at
			ON alert_events(fired_at DESC);

		CREATE TABLE IF NOT EXISTS alert_deliveries (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id      INTEGER NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
			contact_id    INTEGER,
			contact_name  TEXT NOT NULL,
			contact_type  TEXT NOT NULL,
			status        TEXT NOT NULL,
			attempted_at  TEXT NOT NULL,
			error         TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_alert_deliveries_event_id
			ON alert_deliveries(event_id);
	`)
	return err
}

// LoadContacts reads all contacts from the DB ordered by id.
func LoadContacts(db *sql.DB) ([]Contact, error) {
	rows, err := db.Query(`
		SELECT id, name, type, enabled, config, min_severity, sources, created_at, updated_at
		FROM alert_contacts
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var c Contact
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Type, &enabled, &c.Config,
			&c.MinSeverity, &c.Sources, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		c.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// SaveContact inserts a new contact and returns its new ID.
func SaveContact(db *sql.DB, c *Contact) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec(`
		INSERT INTO alert_contacts
			(name, type, enabled, config, min_severity, sources, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		c.Name, c.Type, boolToInt(c.Enabled), c.Config,
		c.MinSeverity, c.Sources, now, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateContact replaces a contact's mutable fields by ID.
func UpdateContact(db *sql.DB, c *Contact) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		UPDATE alert_contacts
		SET name=?, type=?, enabled=?, config=?, min_severity=?, sources=?, updated_at=?
		WHERE id=?
	`,
		c.Name, c.Type, boolToInt(c.Enabled), c.Config,
		c.MinSeverity, c.Sources, now, c.ID,
	)
	return err
}

// ToggleContact flips the enabled flag for a contact.
func ToggleContact(db *sql.DB, id int64, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`UPDATE alert_contacts SET enabled=?, updated_at=? WHERE id=?`,
		boolToInt(enabled), now, id,
	)
	return err
}

// DeleteContact removes a contact by ID.
func DeleteContact(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM alert_contacts WHERE id=?`, id)
	return err
}

// GetContact fetches a single contact by ID.
func GetContact(db *sql.DB, id int64) (*Contact, error) {
	var c Contact
	var enabled int
	var createdAt, updatedAt string
	err := db.QueryRow(`
		SELECT id, name, type, enabled, config, min_severity, sources, created_at, updated_at
		FROM alert_contacts WHERE id=?
	`, id).Scan(
		&c.ID, &c.Name, &c.Type, &enabled, &c.Config,
		&c.MinSeverity, &c.Sources, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled = enabled == 1
	c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &c, nil
}

// WriteEvent persists a fired event + its deliveries.
// Returns the new event ID.
func WriteEvent(db *sql.DB, e Event, deliveries []DeliveryResult) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	tagsJSON := "{}"
	if len(e.Tags) > 0 {
		if b, err := json.Marshal(e.Tags); err == nil {
			tagsJSON = string(b)
		}
	}

	ts := e.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	res, err := db.Exec(`
		INSERT INTO alert_events (ts, source, severity, title, body, tags, fired_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		ts.Format(time.RFC3339),
		string(e.Source),
		string(e.Severity),
		e.Title,
		e.Body,
		tagsJSON,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("insert alert_event: %w", err)
	}

	eventID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for _, d := range deliveries {
		var contactID interface{} = nil
		if d.ContactID > 0 {
			contactID = d.ContactID
		}
		_, err := db.Exec(`
			INSERT INTO alert_deliveries
				(event_id, contact_id, contact_name, contact_type, status, attempted_at, error)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`,
			eventID,
			contactID,
			d.ContactName,
			d.ContactType,
			d.Status,
			d.AttemptedAt.Format(time.RFC3339),
			nullStr(d.Error),
		)
		if err != nil {
			return eventID, fmt.Errorf("insert alert_delivery: %w", err)
		}
	}

	return eventID, nil
}

// QueryEventsRequest holds pagination + filter options
type QueryEventsRequest struct {
	Limit      int
	Offset     int
	Source     string // "" = all
	Severity   string // "" = all
	OnlyFailed bool
	Since      time.Time
}

// AlertEventRow is a joined row for the events list (event + delivery summary)
type AlertEventRow struct {
	ID         int64             `json:"id"`
	FiredAt    time.Time         `json:"fired_at"`
	Source     string            `json:"source"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Body       string            `json:"body"`
	Tags       map[string]string `json:"tags"`
	Deliveries []DeliveryResult  `json:"deliveries"`
}

// QueryEvents returns events with their deliveries, newest first.
func QueryEvents(db *sql.DB, req QueryEventsRequest) ([]AlertEventRow, error) {
	if req.Limit <= 0 {
		req.Limit = 50
	}

	q := `
		SELECT e.id, e.fired_at, e.source, e.severity, e.title, e.body, e.tags
		FROM alert_events e
		WHERE 1=1
	`
	args := []interface{}{}

	if req.Source != "" {
		q += " AND e.source = ?"
		args = append(args, req.Source)
	}
	if req.Severity != "" {
		q += " AND e.severity = ?"
		args = append(args, req.Severity)
	}
	if !req.Since.IsZero() {
		q += " AND e.fired_at >= ?"
		args = append(args, req.Since.Format(time.RFC3339))
	}
	if req.OnlyFailed {
		q += ` AND EXISTS (
			SELECT 1 FROM alert_deliveries d
			WHERE d.event_id = e.id AND d.status = 'failed'
		)`
	}

	q += " ORDER BY e.fired_at DESC LIMIT ? OFFSET ?"
	args = append(args, req.Limit, req.Offset)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AlertEventRow
	for rows.Next() {
		var row AlertEventRow
		var firedAt, tagsJSON string
		if err := rows.Scan(
			&row.ID, &firedAt, &row.Source, &row.Severity,
			&row.Title, &row.Body, &tagsJSON,
		); err != nil {
			return nil, err
		}
		row.FiredAt, _ = time.Parse(time.RFC3339, firedAt)
		_ = json.Unmarshal([]byte(tagsJSON), &row.Tags)
		events = append(events, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch deliveries for each event
	for i, ev := range events {
		deliveries, err := queryDeliveries(db, ev.ID)
		if err != nil {
			return nil, err
		}
		events[i].Deliveries = deliveries
	}

	return events, nil
}

func queryDeliveries(db *sql.DB, eventID int64) ([]DeliveryResult, error) {
	rows, err := db.Query(`
		SELECT contact_id, contact_name, contact_type, status, attempted_at, error
		FROM alert_deliveries
		WHERE event_id = ?
		ORDER BY id
	`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeliveryResult
	for rows.Next() {
		var d DeliveryResult
		var contactID sql.NullInt64
		var attemptedAt string
		var errStr sql.NullString
		if err := rows.Scan(
			&contactID, &d.ContactName, &d.ContactType,
			&d.Status, &attemptedAt, &errStr,
		); err != nil {
			return nil, err
		}
		if contactID.Valid {
			d.ContactID = contactID.Int64
		}
		d.AttemptedAt, _ = time.Parse(time.RFC3339, attemptedAt)
		if errStr.Valid {
			d.Error = errStr.String
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// EventStats holds the summary counts for the stat cards
type EventStats struct {
	Fired      int `json:"fired"`
	Sent       int `json:"sent"`
	Failed     int `json:"failed"`
	Suppressed int `json:"suppressed"`
}

// QueryStats returns delivery counts for the last 24 hours.
func QueryStats(db *sql.DB) (EventStats, error) {
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	var stats EventStats

	err := db.QueryRow(
		`SELECT COUNT(*) FROM alert_events WHERE fired_at >= ?`, since,
	).Scan(&stats.Fired)
	if err != nil {
		return stats, err
	}

	rows, err := db.Query(`
		SELECT d.status, COUNT(*)
		FROM alert_deliveries d
		JOIN alert_events e ON e.id = d.event_id
		WHERE e.fired_at >= ?
		GROUP BY d.status
	`, since)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		switch status {
		case "sent":
			stats.Sent = count
		case "failed":
			stats.Failed = count
		case "suppressed":
			stats.Suppressed = count
		}
	}
	return stats, rows.Err()
}

// ClearEvents deletes all events (and cascades to deliveries).
func ClearEvents(db *sql.DB, before time.Time) error {
	if before.IsZero() {
		_, err := db.Exec(`DELETE FROM alert_events`)
		return err
	}
	_, err := db.Exec(
		`DELETE FROM alert_events WHERE fired_at < ?`,
		before.Format(time.RFC3339),
	)
	return err
}

// helpers
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
