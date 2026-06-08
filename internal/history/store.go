package history

import (
	"path/filepath"
	"strings"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// Record is one persisted scan summary for drift tracking (ARCHITECTURE.md §10.2).
type Record struct {
	GeneratedAt     string  `json:"generatedAt"`
	Source          string  `json:"source"`
	Profile         string  `json:"profile"`
	Findings        int     `json:"findings"`
	Critical        int     `json:"critical"`
	High            int     `json:"high"`
	Medium          int     `json:"medium"`
	Low             int     `json:"low"`
	CriticalPaths   int     `json:"criticalPaths"`
	OverallPassRate float64 `json:"overallPassRate"`
}

// FromReport derives a history Record from a scan report.
func FromReport(r api.Report) Record {
	return Record{
		GeneratedAt:     r.GeneratedAt,
		Source:          r.Source,
		Profile:         r.Profile,
		Findings:        len(r.Findings),
		Critical:        r.Posture.BySeverity[api.SeverityCritical],
		High:            r.Posture.BySeverity[api.SeverityHigh],
		Medium:          r.Posture.BySeverity[api.SeverityMedium],
		Low:             r.Posture.BySeverity[api.SeverityLow],
		CriticalPaths:   r.Posture.CriticalPaths,
		OverallPassRate: r.Posture.OverallPassRate,
	}
}

// Store persists and reads scan records.
type Store interface {
	Append(Record) error
	All() ([]Record, error)
	Close() error
}

// Open returns a Store for the given path. A .sqlite/.db/.kgdb extension selects
// the SQLite backend; anything else is an append-only JSONL file.
func Open(path string) (Store, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sqlite", ".db", ".kgdb":
		return OpenSQLite(path)
	default:
		return OpenFile(path)
	}
}
