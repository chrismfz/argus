package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS detections (
  ip TEXT NOT NULL,
  rule TEXT NOT NULL,
  proto TEXT,
  dst_port INTEGER,
  example_ip TEXT,
  reason TEXT,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER DEFAULT 1,
  flows INTEGER,
  asn TEXT,
  asn_name TEXT,
  country TEXT,
  ptr TEXT,
  PRIMARY KEY (ip, rule)
);

CREATE TABLE IF NOT EXISTS blackholes (
  prefix TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  rule TEXT,
  reason TEXT,
  asn TEXT,
  asn_name TEXT,
  country TEXT,
  ptr TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
  ip TEXT PRIMARY KEY,
  reason TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS ip_profile (
  ip TEXT PRIMARY KEY,
  asn TEXT,
  asn_name TEXT,
  country TEXT,
  ptr TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_profile_updated_at ON ip_profile(updated_at);
CREATE INDEX IF NOT EXISTS idx_ip_profile_last_seen ON ip_profile(last_seen);
`

func InitSQLiteSchema(db *sql.DB) error {
	stmts := strings.Split(schemaSQL, ";")
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("error executing statement: %q: %w", stmt, err)
		}
	}
	return nil
}
