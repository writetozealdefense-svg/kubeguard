package compliance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"testing/fstest"

	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/pkg/api"
)

const fixturesDir = "../../test/fixtures"

func vulnerableFindings(t *testing.T) ([]api.Finding, map[string]bool) {
	t.Helper()
	rs, err := offline.Load(filepath.Join(fixturesDir, "vulnerable.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	prof, _ := checks.ProfileByName("zeal-default")
	findings := checks.Scan(graph.Build(rs), prof)
	return findings, prof.RunnableIDs()
}

func TestLoadEmbeddedPacks(t *testing.T) {
	packs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(packs) != 11 {
		t.Fatalf("got %d packs, want 11", len(packs))
	}
	for _, p := range packs {
		if p.Disclaimer == "" {
			t.Errorf("pack %q missing disclaimer", p.ID)
		}
		for _, c := range p.Controls {
			if c.Assessable && len(c.MapsTo) == 0 {
				t.Errorf("pack %q control %q assessable with no mapping", p.ID, c.ID)
			}
		}
	}
}

// Every mapsTo in every shipped pack must reference a real check id; a typo
// would silently drop a control from the denominator.
func TestEmbeddedPackMappingsResolve(t *testing.T) {
	known := map[string]bool{}
	for _, c := range checks.Registry() {
		known[c.Meta().ID] = true
	}
	packs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, p := range packs {
		for _, c := range p.Controls {
			for _, id := range c.MapsTo {
				if !known[id] {
					t.Errorf("pack %q control %q maps to unknown check %q", p.ID, c.ID, id)
				}
			}
		}
	}
}

// Controls marked assessable:false are excluded from the denominator entirely —
// they are never silently counted as passed (honest-metrics rule 2).
func TestUnassessableControlsExcludedFromDenominator(t *testing.T) {
	packs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	var ce Pack
	for _, p := range packs {
		if p.ID == "cyber-essentials" {
			ce = p
		}
	}
	if ce.ID == "" {
		t.Fatal("cyber-essentials pack not found")
	}
	// Every mapped check ran, but two controls are assessable:false.
	executed := map[string]bool{}
	for _, c := range checks.Registry() {
		executed[c.Meta().ID] = true
	}
	res := ce.Evaluate(executed, map[string]bool{})
	wantAssessable := 0
	for _, c := range ce.Controls {
		if c.Assessable {
			wantAssessable++
		}
	}
	if res.Assessed != wantAssessable {
		t.Errorf("assessed = %d, want %d (only assessable controls)", res.Assessed, wantAssessable)
	}
	if res.Assessed >= len(ce.Controls) {
		t.Errorf("assessed (%d) should be fewer than total controls (%d); assessable:false must be excluded",
			res.Assessed, len(ce.Controls))
	}
}

func TestVulnerableBreachesGolden(t *testing.T) {
	findings, executed := vulnerableFindings(t)
	packs, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	results := EvaluateAll(packs, executed, FiredChecks(findings))

	b, _ := json.MarshalIndent(results, "", "  ")
	b = append(b, '\n')
	goldenPath := filepath.Join(fixturesDir, "golden", "vulnerable.compliance.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		_ = os.WriteFile(goldenPath, b, 0o600)
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(lf(b), lf(want)) {
		t.Errorf("compliance differs from golden\n--- got ---\n%s", b)
	}

	for _, r := range results {
		if r.Assessed == 0 {
			t.Errorf("%s: nothing assessed", r.Framework)
		}
		if r.Breached == 0 {
			t.Errorf("%s: expected breached controls on vulnerable", r.Framework)
		}
		if r.Disclaimer == "" {
			t.Errorf("%s: result missing disclaimer", r.Framework)
		}
		if r.Passed+r.Breached != r.Assessed {
			t.Errorf("%s: passed+breached != assessed", r.Framework)
		}
	}
}

func TestHardenedIsFullPass(t *testing.T) {
	packs, _ := LoadEmbedded()
	prof, _ := checks.ProfileByName("zeal-default")
	// hardened produces no findings → nothing fired.
	results := EvaluateAll(packs, prof.RunnableIDs(), map[string]bool{})
	for _, r := range results {
		if r.Breached != 0 || r.Passed != r.Assessed || r.PassRate != 1.0 {
			t.Errorf("%s: want 100%% of assessed, got %d/%d pass=%v", r.Framework, r.Passed, r.Assessed, r.PassRate)
		}
	}
}

func TestHonestDenominatorSkipsUnrunChecks(t *testing.T) {
	pack := Pack{
		ID: "x", Title: "X", Disclaimer: "d",
		Controls: []Control{
			{ID: "c1", MapsTo: []string{"KG-001"}, Assessable: true},
			{ID: "c2", MapsTo: []string{"KG-001", "KG-999"}, Assessable: true}, // KG-999 never runs
			{ID: "c3", MapsTo: []string{"KG-002"}, Assessable: false},          // not assessable
		},
	}
	executed := map[string]bool{"KG-001": true} // KG-999 and KG-002 did not run
	res := pack.Evaluate(executed, map[string]bool{"KG-001": true})
	if res.Assessed != 1 {
		t.Errorf("assessed = %d, want 1 (only c1; c2 has an unrun check, c3 not assessable)", res.Assessed)
	}
	if res.Breached != 1 || res.PassRate != 0 {
		t.Errorf("c1 should be breached; got breached=%d pass=%v", res.Breached, res.PassRate)
	}
}

func TestRejectsMalformedPacks(t *testing.T) {
	cases := map[string]string{
		"missing id":         "title: T\ndisclaimer: d\ncontrols:\n  - id: a\n    mapsTo: [KG-001]\n    assessable: true\n",
		"missing title":      "id: x\ndisclaimer: d\ncontrols:\n  - id: a\n    mapsTo: [KG-001]\n    assessable: true\n",
		"missing disclaimer": "id: x\ntitle: T\ncontrols:\n  - id: a\n    mapsTo: [KG-001]\n    assessable: true\n",
		"no controls":        "id: x\ntitle: T\ndisclaimer: d\ncontrols: []\n",
		"assessable empty":   "id: x\ntitle: T\ndisclaimer: d\ncontrols:\n  - id: a\n    assessable: true\n",
		"unknown key":        "id: x\ntitle: T\ndisclaimer: d\nbogus: 1\ncontrols:\n  - id: a\n    mapsTo: [KG-001]\n    assessable: true\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePack([]byte(doc)); err == nil {
				t.Errorf("%s: expected error, got nil", name)
			}
		})
	}
}

func TestParseValidPack(t *testing.T) {
	doc := "id: x\ntitle: T\nversion: \"1\"\ndisclaimer: d\ncontrols:\n  - id: a\n    title: A\n    mapsTo: [KG-001]\n    assessable: true\n"
	p, err := ParsePack([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePack: %v", err)
	}
	if p.ID != "x" || len(p.Controls) != 1 {
		t.Errorf("unexpected pack: %+v", p)
	}
}

// A new pack dropped into a filesystem is evaluated with no code change.
func TestAddPackRequiresNoCodeChange(t *testing.T) {
	fsys := fstest.MapFS{
		"custom.yaml": {Data: []byte("id: custom\ntitle: Custom\ndisclaimer: indicative only\ncontrols:\n  - id: K1\n    title: priv\n    mapsTo: [KG-001]\n    assessable: true\n")},
	}
	packs, err := LoadFS(fsys)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("got %d packs, want 1", len(packs))
	}
	res := packs[0].Evaluate(map[string]bool{"KG-001": true}, map[string]bool{"KG-001": true})
	if res.Assessed != 1 || res.Breached != 1 {
		t.Errorf("custom pack not evaluated: %+v", res)
	}
}

func TestBuildEvidence(t *testing.T) {
	findings, executed := vulnerableFindings(t)
	packs, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	rep := api.Report{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Source:      "vulnerable.yaml",
		Profile:     "zeal-default",
		Findings:    findings,
	}
	evs := BuildEvidence(rep, packs, executed)
	if len(evs) != len(packs) {
		t.Fatalf("got %d evidence packs, want %d", len(evs), len(packs))
	}
	for _, ev := range evs {
		if ev.GeneratedAt != "2026-01-01T00:00:00Z" || ev.Source != "vulnerable.yaml" || ev.Profile != "zeal-default" {
			t.Errorf("%s: report metadata not carried through", ev.ID)
		}
		if ev.Passed+ev.Breached != ev.Assessed {
			t.Errorf("%s: passed+breached != assessed", ev.ID)
		}
		if len(ev.Controls) != ev.Assessed {
			t.Errorf("%s: controls listed (%d) != assessed (%d)", ev.ID, len(ev.Controls), ev.Assessed)
		}
		if ev.Disclaimer == "" {
			t.Errorf("%s: missing disclaimer", ev.ID)
		}
		for _, c := range ev.Controls {
			if c.Breached != (len(c.Findings) > 0) {
				t.Errorf("%s/%s: breached=%v but %d findings", ev.ID, c.ControlID, c.Breached, len(c.Findings))
			}
			if !sort.StringsAreSorted(c.MapsTo) {
				t.Errorf("%s/%s: mapsTo not sorted: %v", ev.ID, c.ControlID, c.MapsTo)
			}
			for _, f := range c.Findings {
				// Every breaching finding must be one this control maps to.
				if !contains(c.MapsTo, f.ID) {
					t.Errorf("%s/%s: finding %q not in mapsTo", ev.ID, c.ControlID, f.ID)
				}
			}
		}
		// cyber-essentials drops its two assessable:false controls.
		if ev.ID == "cyber-essentials" && ev.Assessed != 3 {
			t.Errorf("cyber-essentials assessed = %d, want 3 (assessable:false excluded)", ev.Assessed)
		}
	}
}

func TestBuildEvidenceNoFindings(t *testing.T) {
	packs, _ := LoadEmbedded()
	prof, _ := checks.ProfileByName("zeal-default")
	rep := api.Report{GeneratedAt: "t", Profile: "zeal-default"} // hardened: no findings
	evs := BuildEvidence(rep, packs, prof.RunnableIDs())
	for _, ev := range evs {
		if ev.Breached != 0 || ev.Passed != ev.Assessed || (ev.Assessed > 0 && ev.PassRate != 1.0) {
			t.Errorf("%s: no findings should pass all assessed, got breached=%d pass=%v", ev.ID, ev.Breached, ev.PassRate)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestSummarize(t *testing.T) {
	findings := []api.Finding{
		{ID: "KG-001", Severity: api.SeverityCritical},
		{ID: "KG-003", Severity: api.SeverityHigh},
		{ID: "KG-010", Severity: api.SeverityLow},
	}
	paths := []api.AttackPath{
		{Severity: api.SeverityCritical},
		{Severity: api.SeverityMedium},
	}
	results := []api.FrameworkResult{
		{Assessed: 4, Breached: 1},
		{Assessed: 6, Breached: 3},
	}
	s := Summarize(findings, paths, results)
	if s.TotalFindings != 3 || s.BySeverity[api.SeverityCritical] != 1 || s.BySeverity[api.SeverityHigh] != 1 {
		t.Errorf("severity tally off: %+v", s)
	}
	if s.CriticalPaths != 1 {
		t.Errorf("criticalPaths = %d, want 1", s.CriticalPaths)
	}
	if s.ControlsAssessed != 10 || s.ControlsBreached != 4 {
		t.Errorf("controls = %d/%d, want 10/4", s.ControlsBreached, s.ControlsAssessed)
	}
	if s.OverallPassRate != 0.6 { // (10-4)/10
		t.Errorf("overallPassRate = %v, want 0.6", s.OverallPassRate)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(nil, nil, nil)
	if s.OverallPassRate != 0 || s.ControlsAssessed != 0 {
		t.Errorf("empty posture should be zero-valued, got %+v", s)
	}
}

func lf(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
