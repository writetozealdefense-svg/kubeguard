package history

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS scans (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  generated_at      TEXT,
  source            TEXT,
  profile           TEXT,
  findings          INTEGER,
  critical          INTEGER,
  high              INTEGER,
  medium            INTEGER,
  low               INTEGER,
  critical_paths    INTEGER,
  overall_pass_rate REAL
);`

type sqliteStore struct{ db *sql.DB }

// OpenSQLite opens (creating if needed) a SQLite history store at path.
func OpenSQLite(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Append(r Record) error {
	_, err := s.db.Exec(
		`INSERT INTO scans
		 (generated_at, source, profile, findings, critical, high, medium, low, critical_paths, overall_pass_rate)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.GeneratedAt, r.Source, r.Profile, r.Findings,
		r.Critical, r.High, r.Medium, r.Low, r.CriticalPaths, r.OverallPassRate)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	return nil
}

func (s *sqliteStore) All() ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT generated_at, source, profile, findings, critical, high, medium, low, critical_paths, overall_pass_rate
		 FROM scans ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.GeneratedAt, &r.Source, &r.Profile, &r.Findings,
			&r.Critical, &r.High, &r.Medium, &r.Low, &r.CriticalPaths, &r.OverallPassRate); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) Close() error { return s.db.Close() }
