package detection

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ExcludeEntry is one row in detection_excludes.
type ExcludeEntry struct {
	ID        int64     `json:"id"`
	CIDR      string    `json:"cidr"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

// InitExcludesTable creates the detection_excludes table if it doesn't exist.
// Safe to call on every startup.
func InitExcludesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS detection_excludes (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			cidr       TEXT    NOT NULL UNIQUE,
			label      TEXT    NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("InitExcludesTable: %w", err)
	}
	return nil
}

// MigrateExcludesFromFile reads the legacy flat file and inserts any entries
// that are not already in the DB. It is idempotent: safe to call on every
// startup. Returns the number of rows inserted.
func MigrateExcludesFromFile(db *sql.DB, path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil // nothing to migrate
	}
	if err != nil {
		return 0, fmt.Errorf("MigrateExcludesFromFile open: %w", err)
	}
	defer f.Close()

	inserted := 0
	sc := bufio.NewScanner(f)
	var currentLabel string

	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		// Pure comment lines may carry a label for the block that follows.
		if strings.HasPrefix(line, "#") {
			// Strip '#' and leading whitespace to use as label hint.
			currentLabel = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}
		if line == "" {
			currentLabel = ""
			continue
		}

		// Strip inline comment.
		if i := strings.Index(line, "#"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// First token only.
		if i := strings.IndexAny(line, " \t"); i != -1 {
			line = strings.TrimSpace(line[:i])
		}

		// Normalise: plain IPs become /32 or /128 CIDRs.
		cidr := normalizeEntry(line)
		if cidr == "" {
			continue
		}

		_, err := db.Exec(
			`INSERT OR IGNORE INTO detection_excludes (cidr, label) VALUES (?, ?)`,
			cidr, currentLabel,
		)
		if err != nil {
			return inserted, fmt.Errorf("MigrateExcludesFromFile insert %q: %w", cidr, err)
		}
		inserted++
	}
	return inserted, sc.Err()
}

// normalizeEntry validates and normalises an IP or CIDR string.
// Returns "" on invalid input.
func normalizeEntry(s string) string {
	// Try as CIDR first.
	if ip, nw, err := net.ParseCIDR(s); err == nil {
		_ = ip
		return nw.String() // canonical form
	}
	// Try as plain IP.
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32"
		}
		return ip.String() + "/128"
	}
	return ""
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

// ListExcludes returns all rows ordered by id.
func ListExcludes(db *sql.DB) ([]ExcludeEntry, error) {
	rows, err := db.Query(
		`SELECT id, cidr, label, created_at FROM detection_excludes ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ExcludeEntry
	for rows.Next() {
		var e ExcludeEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Label, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddExclude inserts a new entry. Returns the new row ID.
// Returns an error (with a friendly message) on duplicate CIDR.
func AddExclude(db *sql.DB, cidr, label string) (int64, error) {
	cidr = normalizeEntry(strings.TrimSpace(cidr))
	if cidr == "" {
		return 0, fmt.Errorf("invalid IP or CIDR: %q", cidr)
	}
	res, err := db.Exec(
		`INSERT INTO detection_excludes (cidr, label) VALUES (?, ?)`,
		cidr, strings.TrimSpace(label),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return 0, fmt.Errorf("entry already exists: %s", cidr)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteExclude removes a row by ID. Returns sql.ErrNoRows if not found.
func DeleteExclude(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM detection_excludes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateExclude replaces the cidr and/or label of an existing row.
func UpdateExclude(db *sql.DB, id int64, cidr, label string) error {
	cidr = normalizeEntry(strings.TrimSpace(cidr))
	if cidr == "" {
		return fmt.Errorf("invalid IP or CIDR")
	}
	res, err := db.Exec(
		`UPDATE detection_excludes SET cidr = ?, label = ? WHERE id = ?`,
		cidr, strings.TrimSpace(label), id,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return fmt.Errorf("entry already exists: %s", cidr)
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ── In-memory reload ──────────────────────────────────────────────────────────

// LoadProtectedFromDB reads all rows from detection_excludes and refreshes the
// in-memory protectedIPs / protectedPrefixes used by IsProtected().
// Drop-in companion to the existing LoadProtectedFromFile.
func LoadProtectedFromDB(db *sql.DB) error {
	entries, err := ListExcludes(db)
	if err != nil {
		return fmt.Errorf("LoadProtectedFromDB: %w", err)
	}

	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	for _, e := range entries {
		// The stored value is already normalised as x.x.x.x/32 or a CIDR.
		// Parse it uniformly as a CIDR.
		_, nw, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			DlogEngine("LoadProtectedFromDB: skipping bad entry %q: %v", e.CIDR, err)
			continue
		}
		ones, bits := nw.Mask.Size()
		if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
			// Store /32 and /128 as exact IPs for the fast-path map.
			ips[nw.IP.String()] = struct{}{}
		} else {
			cidrs = append(cidrs, nw)
		}
	}

	protectedLock.Lock()
	protectedIPs = ips
	protectedPrefixes = cidrs
	protectedLoadedAt = time.Now().UTC()
	protectedLock.Unlock()

	DlogEngine("LoadProtectedFromDB: %d exact IPs, %d CIDRs", len(ips), len(cidrs))
	return nil
}
