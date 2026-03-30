package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"argus/internal/alerter"
)

// ── Contacts ──────────────────────────────────────────────────────────────────

// GET /alerter/contacts
func handleAlerterContactsList(w http.ResponseWriter, r *http.Request) {
	contacts, err := alerter.LoadContacts(DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if contacts == nil {
		contacts = []alerter.Contact{}
	}
	jsonOK(w, contacts)
}

// POST /alerter/contacts
func handleAlerterContactsCreate(w http.ResponseWriter, r *http.Request) {
	var c alerter.Contact
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateContact(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := alerter.SaveContact(DB, &c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.ID = id
	reloadAlerter()
	jsonOK(w, c)
}

// PUT /alerter/contacts/{id}
func handleAlerterContactsUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := alerterIDFromPath(r.URL.Path, "/alerter/contacts/")
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var c alerter.Contact
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	c.ID = id
	if err := validateContact(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := alerter.UpdateContact(DB, &c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reloadAlerter()
	jsonOK(w, c)
}

// DELETE /alerter/contacts/{id}
func handleAlerterContactsDelete(w http.ResponseWriter, r *http.Request) {
	id, err := alerterIDFromPath(r.URL.Path, "/alerter/contacts/")
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := alerter.DeleteContact(DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reloadAlerter()
	jsonOK(w, map[string]bool{"ok": true})
}

// PATCH /alerter/contacts/{id}/toggle
func handleAlerterContactsToggle(w http.ResponseWriter, r *http.Request) {
	// Path: /alerter/contacts/{id}/toggle
	trimmed := strings.TrimSuffix(r.URL.Path, "/toggle")
	id, err := alerterIDFromPath(trimmed, "/alerter/contacts/")
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := alerter.ToggleContact(DB, id, body.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reloadAlerter()
	jsonOK(w, map[string]bool{"ok": true})
}

// POST /alerter/contacts/{id}/test
func handleAlerterContactsTest(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimSuffix(r.URL.Path, "/test")
	id, err := alerterIDFromPath(trimmed, "/alerter/contacts/")
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if alerter.Global == nil {
		http.Error(w, "alerter not initialized", http.StatusServiceUnavailable)
		return
	}
	result, err := alerter.Global.SendTest(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result == nil {
		http.Error(w, "contact not found", http.StatusNotFound)
		return
	}
	jsonOK(w, result)
}

// ── Events ────────────────────────────────────────────────────────────────────

// GET /alerter/events
func handleAlerterEventsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	req := alerter.QueryEventsRequest{
		Source:     q.Get("source"),
		Severity:   q.Get("severity"),
		OnlyFailed: q.Get("only_failed") == "1" || q.Get("only_failed") == "true",
	}

	if lim := q.Get("limit"); lim != "" {
		req.Limit, _ = strconv.Atoi(lim)
	}
	if off := q.Get("offset"); off != "" {
		req.Offset, _ = strconv.Atoi(off)
	}
	if since := q.Get("since"); since != "" {
		req.Since, _ = time.Parse(time.RFC3339, since)
	}

	events, err := alerter.QueryEvents(DB, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []alerter.AlertEventRow{}
	}
	jsonOK(w, events)
}

// DELETE /alerter/events
func handleAlerterEventsClear(w http.ResponseWriter, r *http.Request) {
	var before time.Time
	if b := r.URL.Query().Get("before"); b != "" {
		before, _ = time.Parse(time.RFC3339, b)
	}
	if err := alerter.ClearEvents(DB, before); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// GET /alerter/events/stats
func handleAlerterEventsStats(w http.ResponseWriter, r *http.Request) {
	stats, err := alerter.QueryStats(DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, stats)
}

// ── SSE stream ────────────────────────────────────────────────────────────────

// GET /alerter/stream — Server-Sent Events, one FiredEvent per line
func handleAlerterStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send a heartbeat comment immediately so the browser knows it's connected
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-ticker.C:
			// Heartbeat keepalive — prevents nginx/browser from closing idle stream
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case fe, ok := <-alerter.Broadcast:
			if !ok {
				return
			}
			data, err := alerter.SSEMarshal(fe)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────


func alerterIDFromPath(path, prefix string) (int64, error) {
	raw := strings.TrimPrefix(path, prefix)
	raw = strings.TrimSuffix(raw, "/")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad id: %s", raw)
	}
	return id, nil
}

func validateContact(c *alerter.Contact) error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	switch c.Type {
	case "slack", "smtp", "log":
	default:
		return fmt.Errorf("type must be slack, smtp, or log")
	}
	switch c.MinSeverity {
	case alerter.SeverityInfo, alerter.SeverityWarning, alerter.SeverityCritical:
	case "":
		c.MinSeverity = alerter.SeverityInfo
	default:
		return fmt.Errorf("min_severity must be info, warning, or critical")
	}
	if c.Config == "" {
		c.Config = "{}"
	}
	return nil
}

func reloadAlerter() {
	if alerter.Global == nil {
		return
	}
	if err := alerter.Global.Reload(); err != nil {
		// Non-fatal — log only
		_ = err
	}
}
