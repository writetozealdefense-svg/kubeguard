package history

import (
	"path/filepath"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func sampleRecords() []Record {
	return []Record{
		{Source: "vulnerable", OverallPassRate: 0.03, Findings: 19, Critical: 4},
		{Source: "partial", OverallPassRate: 0.40, Findings: 8, Critical: 1},
		{Source: "hardened", OverallPassRate: 1.00, Findings: 0},
	}
}

func TestBackendsRoundTripAndTrend(t *testing.T) {
	backends := map[string]string{
		"jsonl":  "hist.jsonl",
		"sqlite": "hist.sqlite",
	}
	for name, file := range backends {
		t.Run(name, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), file))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = store.Close() }()

			for _, r := range sampleRecords() {
				if err := store.Append(r); err != nil {
					t.Fatalf("Append: %v", err)
				}
			}
			got, err := store.All()
			if err != nil {
				t.Fatalf("All: %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("got %d records, want 3", len(got))
			}
			// Control-pass trends upward across the three fixtures.
			for i := 1; i < len(got); i++ {
				if got[i].OverallPassRate < got[i-1].OverallPassRate {
					t.Errorf("pass rate not trending up: %v", got)
				}
			}
			if got[0].Source != "vulnerable" || got[2].OverallPassRate != 1.0 {
				t.Errorf("records out of order or wrong: %+v", got)
			}
		})
	}
}

func TestOpenSelectsBackend(t *testing.T) {
	dir := t.TempDir()
	if s, err := Open(filepath.Join(dir, "x.kgdb")); err != nil {
		t.Errorf(".kgdb should open: %v", err)
	} else {
		_ = s.Close()
	}
	if s, err := Open(filepath.Join(dir, "x.log")); err != nil {
		t.Errorf("non-db ext should open as file: %v", err)
	} else {
		_ = s.Close()
	}
}

func TestFileAllMissingIsEmpty(t *testing.T) {
	store, _ := OpenFile(filepath.Join(t.TempDir(), "none.jsonl"))
	got, err := store.All()
	if err != nil || got != nil {
		t.Errorf("missing history should be empty, got %v err %v", got, err)
	}
}

func TestFromReport(t *testing.T) {
	rep := api.Report{
		GeneratedAt: "t", Source: "s", Profile: "zeal-default",
		Findings: []api.Finding{{Severity: api.SeverityCritical}, {Severity: api.SeverityLow}},
		Posture: api.PostureSummary{
			BySeverity:      map[api.Severity]int{api.SeverityCritical: 1, api.SeverityLow: 1},
			CriticalPaths:   2,
			OverallPassRate: 0.5,
		},
	}
	r := FromReport(rep)
	if r.Findings != 2 || r.Critical != 1 || r.Low != 1 || r.CriticalPaths != 2 || r.OverallPassRate != 0.5 {
		t.Errorf("FromReport mismapped: %+v", r)
	}
}
