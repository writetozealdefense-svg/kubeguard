package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/attack"
	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/compliance"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const fixturesDir = "../../test/fixtures"

func buildReport(t *testing.T, file string) api.Report {
	t.Helper()
	rs, err := offline.Load(filepath.Join(fixturesDir, file))
	if err != nil {
		t.Fatal(err)
	}
	g := graph.Build(rs)
	prof, _ := checks.ProfileByName("zeal-default")
	findings := checks.Scan(g, prof)
	paths := attack.BuildPaths(g, false)
	packs, _ := compliance.LoadEmbedded()
	fw := compliance.EvaluateAll(packs, prof.RunnableIDs(), compliance.FiredChecks(findings))
	return api.Report{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Source:      file, Profile: prof.Name,
		Findings:   findings,
		Paths:      paths,
		Posture:    compliance.Summarize(findings, paths, fw),
		Compliance: fw,
	}
}

func TestSARIFValid(t *testing.T) {
	rep := buildReport(t, "vulnerable.yaml")
	var buf bytes.Buffer
	if err := SARIF(&buf, rep); err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	// Must parse as a SARIF document.
	if _, err := sarif.FromBytes(buf.Bytes()); err != nil {
		t.Fatalf("output is not valid SARIF: %v", err)
	}

	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || !strings.Contains(doc.Schema, "sarif") {
		t.Errorf("bad header: version=%q schema=%q", doc.Version, doc.Schema)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "KubeGuard" {
		t.Fatalf("unexpected runs/tool: %+v", doc.Runs)
	}
	if len(doc.Runs[0].Results) != len(rep.Findings) {
		t.Errorf("results = %d, want %d", len(doc.Runs[0].Results), len(rep.Findings))
	}
	valid := map[string]bool{"error": true, "warning": true, "note": true}
	for _, r := range doc.Runs[0].Results {
		if !valid[r.Level] {
			t.Errorf("invalid SARIF level %q", r.Level)
		}
	}
}

func TestHTMLRendersChainAndCompliance(t *testing.T) {
	rep := buildReport(t, "vulnerable.yaml")
	hist := []history.Record{
		{Source: "vulnerable", OverallPassRate: 0.03},
		{Source: "hardened", OverallPassRate: 1.0},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, rep, hist); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Cluster-admin takeover via checkout",    // attack chain
		"ClusterAdmin",                           // path node
		"T1611",                                  // ATT&CK technique
		"CIS Kubernetes Benchmark",               // compliance breach view
		"Attack Paths", "Compliance", "Findings", // tabs
		"<polyline",                  // SVG trend chart
		"Indicative control mapping", // honest-metrics disclaimer
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestConsoleColorToggle(t *testing.T) {
	rep := buildReport(t, "vulnerable.yaml")
	var withColor, noColor bytes.Buffer
	if err := Console(&withColor, rep, true); err != nil {
		t.Fatal(err)
	}
	if err := Console(&noColor, rep, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withColor.String(), "\033[") {
		t.Error("colour output should contain ANSI escapes")
	}
	if strings.Contains(noColor.String(), "\033[") {
		t.Error("non-colour output must not contain ANSI escapes")
	}
}

func TestJSONDeterministic(t *testing.T) {
	rep := buildReport(t, "vulnerable.yaml")
	var a, b bytes.Buffer
	_ = JSON(&a, rep)
	_ = JSON(&b, rep)
	if a.String() != b.String() {
		t.Error("JSON output is not deterministic")
	}
}

func TestHardenedConsoleClean(t *testing.T) {
	rep := buildReport(t, "hardened.yaml")
	var buf bytes.Buffer
	if err := Console(&buf, rep, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Errorf("hardened console should report no findings:\n%s", buf.String())
	}
}
