package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BlackholeHistorySummary is one row in the grouped view (one per IP).
type BlackholeHistorySummary struct {
	IP                string `json:"ip"`
	Events            int    `json:"events"`
	Announcements     int    `json:"announcements"`
	Withdrawals       int    `json:"withdrawals"`
	Expirations       int    `json:"expirations"`
	Skips             int    `json:"skips"`
	FirstSeen         string `json:"first_seen"`
	LastSeen          string `json:"last_seen"`
	LastEvent         string `json:"last_event"`
	LastRule          string `json:"last_rule,omitempty"`
	LastReason        string `json:"last_reason,omitempty"`
	LastSource        string `json:"last_source,omitempty"`
	CurrentlyActive   bool   `json:"currently_active"`
	ActivePrefix      string `json:"active_prefix,omitempty"`
	ActiveExpiresAt   string `json:"active_expires_at,omitempty"`
	ASN               string `json:"asn,omitempty"`
	ASNName           string `json:"asn_name,omitempty"`
	Country           string `json:"country,omitempty"`
	PTR               string `json:"ptr,omitempty"`
}

// BlackholeHistoryEvent is one raw event row in the per-IP timeline view.
type BlackholeHistoryEvent struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"ts"`
	IP         string `json:"ip"`
	Prefix     string `json:"prefix"`
	Event      string `json:"event"`
	Source     string `json:"source,omitempty"`
	Rule       string `json:"rule,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	ASN        string `json:"asn,omitempty"`
	ASNName    string `json:"asn_name,omitempty"`
	Country    string `json:"country,omitempty"`
	PTR        string `json:"ptr,omitempty"`
}

// handleBlackholeHistory returns either the grouped summary (default) or the
// per-IP timeline when ?ip=… is supplied.
func handleBlackholeHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if DB == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		handleBlackholeHistoryByIP(w, r, ip)
		return
	}
	handleBlackholeHistorySummary(w, r)
}

func handleBlackholeHistorySummary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 200)
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	offset := atoiDefault(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	sortBy := "last_seen"
	switch strings.ToLower(q.Get("sort")) {
	case "count", "events":
		sortBy = "events"
	case "first", "first_seen":
		sortBy = "first_seen"
	case "ip":
		sortBy = "ip"
	}

	filter := strings.TrimSpace(q.Get("q"))

	var where []string
	var args []interface{}
	if filter != "" {
		where = append(where,
			"(ip LIKE ? OR ptr LIKE ? OR asn_name LIKE ? OR country LIKE ? OR rule LIKE ?)")
		like := "%" + filter + "%"
		args = append(args, like, like, like, like, like)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	orderClause := "ORDER BY MAX(ts) DESC"
	switch sortBy {
	case "events":
		orderClause = "ORDER BY events DESC, MAX(ts) DESC"
	case "first_seen":
		orderClause = "ORDER BY MIN(ts) DESC"
	case "ip":
		orderClause = "ORDER BY ip ASC"
	}

	query := fmt.Sprintf(`
		SELECT
			ip,
			COUNT(*) AS events,
			SUM(CASE WHEN event='announced' THEN 1 ELSE 0 END) AS announcements,
			SUM(CASE WHEN event='withdrawn' THEN 1 ELSE 0 END) AS withdrawals,
			SUM(CASE WHEN event='expired'   THEN 1 ELSE 0 END) AS expirations,
			SUM(CASE WHEN event='skipped'   THEN 1 ELSE 0 END) AS skips,
			MIN(ts) AS first_seen,
			MAX(ts) AS last_seen
		FROM blackhole_events
		%s
		GROUP BY ip
		%s
		LIMIT ? OFFSET ?
	`, whereClause, orderClause)

	args = append(args, limit, offset)

	rows, err := DB.Query(query, args...)
	if err != nil {
		log.Printf("[blackhole-history] summary query failed: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var summaries []BlackholeHistorySummary
	for rows.Next() {
		var s BlackholeHistorySummary
		if err := rows.Scan(
			&s.IP, &s.Events,
			&s.Announcements, &s.Withdrawals, &s.Expirations, &s.Skips,
			&s.FirstSeen, &s.LastSeen,
		); err != nil {
			log.Printf("[blackhole-history] scan failed: %v", err)
			continue
		}
		summaries = append(summaries, s)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[blackhole-history] rows error: %v", err)
	}

	// Enrich each row with last-event details + current active state. Done in
	// a loop because LIMIT is small (default 200) — keeps each subquery indexed
	// by ip and avoids a sprawling window-function query.
	for i := range summaries {
		enrichSummary(&summaries[i])
	}

	var total int
	totalQuery := "SELECT COUNT(DISTINCT ip) FROM blackhole_events"
	if whereClause != "" {
		totalQuery += " " + whereClause
	}
	if err := DB.QueryRow(totalQuery, args[:len(args)-2]...).Scan(&total); err != nil {
		log.Printf("[blackhole-history] total count failed: %v", err)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"results": summaries,
	})
}

func enrichSummary(s *BlackholeHistorySummary) {
	var (
		event, source, rule, reason sql.NullString
		asn, asnName, country, ptr  sql.NullString
	)
	err := DB.QueryRow(`
		SELECT event, source, rule, reason, asn, asn_name, country, ptr
		FROM blackhole_events
		WHERE ip = ?
		ORDER BY ts DESC, id DESC
		LIMIT 1
	`, s.IP).Scan(&event, &source, &rule, &reason, &asn, &asnName, &country, &ptr)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("[blackhole-history] last-event lookup failed ip=%s: %v", s.IP, err)
	}
	if event.Valid {
		s.LastEvent = event.String
	}
	if source.Valid {
		s.LastSource = source.String
	}
	if rule.Valid {
		s.LastRule = rule.String
	}
	if reason.Valid {
		s.LastReason = reason.String
	}
	if asn.Valid {
		s.ASN = asn.String
	}
	if asnName.Valid {
		s.ASNName = asnName.String
	}
	if country.Valid {
		s.Country = country.String
	}
	if ptr.Valid {
		s.PTR = ptr.String
	}

	var (
		prefix, expires sql.NullString
	)
	err = DB.QueryRow(`
		SELECT prefix, expires_at
		FROM blackholes
		WHERE prefix LIKE ?
		LIMIT 1
	`, s.IP+"/%").Scan(&prefix, &expires)
	if err == nil {
		s.CurrentlyActive = true
		if prefix.Valid {
			s.ActivePrefix = prefix.String
		}
		if expires.Valid {
			s.ActiveExpiresAt = expires.String
		}
	} else if err != sql.ErrNoRows {
		log.Printf("[blackhole-history] active lookup failed ip=%s: %v", s.IP, err)
	}
}

func handleBlackholeHistoryByIP(w http.ResponseWriter, r *http.Request, ip string) {
	if net.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 500)
	if limit <= 0 || limit > 5000 {
		limit = 500
	}

	rows, err := DB.Query(`
		SELECT id, ts, ip, prefix, event,
		       COALESCE(source,''), COALESCE(rule,''), COALESCE(reason,''),
		       COALESCE(ttl_seconds, 0),
		       COALESCE(asn,''), COALESCE(asn_name,''), COALESCE(country,''), COALESCE(ptr,'')
		FROM blackhole_events
		WHERE ip = ?
		ORDER BY ts DESC, id DESC
		LIMIT ?
	`, ip, limit)
	if err != nil {
		log.Printf("[blackhole-history] per-ip query failed ip=%s: %v", ip, err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []BlackholeHistoryEvent
	for rows.Next() {
		var e BlackholeHistoryEvent
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.IP, &e.Prefix, &e.Event,
			&e.Source, &e.Rule, &e.Reason, &e.TTLSeconds,
			&e.ASN, &e.ASNName, &e.Country, &e.PTR,
		); err != nil {
			log.Printf("[blackhole-history] per-ip scan failed: %v", err)
			continue
		}
		events = append(events, e)
	}

	summary := BlackholeHistorySummary{IP: ip}
	_ = DB.QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN event='announced' THEN 1 ELSE 0 END),
			SUM(CASE WHEN event='withdrawn' THEN 1 ELSE 0 END),
			SUM(CASE WHEN event='expired'   THEN 1 ELSE 0 END),
			SUM(CASE WHEN event='skipped'   THEN 1 ELSE 0 END),
			MIN(ts), MAX(ts)
		FROM blackhole_events
		WHERE ip = ?
	`, ip).Scan(
		&summary.Events,
		&summary.Announcements, &summary.Withdrawals,
		&summary.Expirations, &summary.Skips,
		&summary.FirstSeen, &summary.LastSeen,
	)
	enrichSummary(&summary)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"summary": summary,
		"events":  events,
	})
}

// handleBlackholeHistoryPrune is the admin endpoint for removing history rows.
// POST body (JSON):
//   {"ip": "1.2.3.4"}             — delete all events for one IP
//   {"older_than_days": 30}        — delete events older than N days
//   {"all": true}                  — wipe entire table
// Exactly one of those fields must be set.
func handleBlackholeHistoryPrune(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if DB == nil {
		http.Error(w, "DB not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		IP             string `json:"ip"`
		OlderThanDays  int    `json:"older_than_days"`
		All            bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	chosen := 0
	if req.IP != "" {
		chosen++
	}
	if req.OlderThanDays > 0 {
		chosen++
	}
	if req.All {
		chosen++
	}
	if chosen != 1 {
		http.Error(w, "Specify exactly one of: ip, older_than_days, all", http.StatusBadRequest)
		return
	}

	var (
		res sql.Result
		err error
	)
	switch {
	case req.IP != "":
		if net.ParseIP(req.IP) == nil {
			http.Error(w, "Invalid IP", http.StatusBadRequest)
			return
		}
		res, err = DB.Exec(`DELETE FROM blackhole_events WHERE ip = ?`, req.IP)
	case req.OlderThanDays > 0:
		cutoff := time.Now().Add(-time.Duration(req.OlderThanDays) * 24 * time.Hour).Format(time.RFC3339)
		res, err = DB.Exec(`DELETE FROM blackhole_events WHERE ts < ?`, cutoff)
	case req.All:
		res, err = DB.Exec(`DELETE FROM blackhole_events`)
	}
	if err != nil {
		log.Printf("[blackhole-history] prune failed: %v", err)
		http.Error(w, "prune failed", http.StatusInternalServerError)
		return
	}
	deleted, _ := res.RowsAffected()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"deleted": deleted,
	})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
