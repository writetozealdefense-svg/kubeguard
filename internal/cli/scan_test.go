package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

const fixturesDir = "../../test/fixtures"

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestScanJSONVulnerable(t *testing.T) {
	out, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "json")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var rep api.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse json: %v\n%s", err, out)
	}
	if rep.Profile != "zeal-default" {
		t.Errorf("profile = %q, want zeal-default", rep.Profile)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestScanConsoleHardened(t *testing.T) {
	out, err := runCLI(t, "scan", "-i", fixturesDir+"/hardened.yaml")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected clean console output, got:\n%s", out)
	}
}

func TestScanFailOnGate(t *testing.T) {
	// vulnerable at/above high → coded gate error (exit 2).
	_, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "json", "--fail-on", "high")
	var ce *codedError
	if !isCodedError(err, &ce) {
		t.Fatalf("expected gate breach, got %v", err)
	}
	if ce.code != exitGateHit {
		t.Errorf("gate code = %d, want %d", ce.code, exitGateHit)
	}
	// hardened → no breach.
	if _, err := runCLI(t, "scan", "-i", fixturesDir+"/hardened.yaml", "--fail-on", "critical"); err != nil {
		t.Errorf("hardened fail-on should pass, got %v", err)
	}
}

func TestScanFormats(t *testing.T) {
	for _, f := range []string{"json", "sarif", "html", "console"} {
		out, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", f)
		if err != nil {
			t.Errorf("format %s: %v", f, err)
		}
		if len(out) == 0 {
			t.Errorf("format %s: empty output", f)
		}
	}
}

func TestScanEvidenceExport(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "evidence", "-o", dir); err != nil {
		t.Fatalf("evidence scan: %v", err)
	}
	for _, name := range []string{
		"uk-gdpr-dpa-2018.evidence.html", "uk-gdpr-dpa-2018.evidence.json",
		"ncsc-caf-4.evidence.html", "cyber-essentials.evidence.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing evidence file %s: %v", name, err)
		}
	}
	// The JSON sibling parses into the reused api type with an honest denominator.
	b, err := os.ReadFile(filepath.Join(dir, "cyber-essentials.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ep api.EvidencePack
	if err := json.Unmarshal(b, &ep); err != nil {
		t.Fatalf("parse evidence json: %v", err)
	}
	if ep.Assessed != 3 { // 2 of 5 controls are assessable:false
		t.Errorf("cyber-essentials assessed = %d, want 3", ep.Assessed)
	}
}

func TestScanEvidenceRequiresOutputDir(t *testing.T) {
	if _, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "evidence"); err == nil {
		t.Error("-f evidence without -o should error")
	}
}

func TestScanHistoryRoundTrip(t *testing.T) {
	hp := filepath.Join(t.TempDir(), "h.jsonl")
	for _, fx := range []string{"vulnerable.yaml", "hardened.yaml"} {
		if _, err := runCLI(t, "scan", "-i", fixturesDir+"/"+fx, "-f", "json", "--history", hp); err != nil {
			t.Fatalf("scan %s: %v", fx, err)
		}
	}
	if _, err := os.Stat(hp); err != nil {
		t.Errorf("history file not written: %v", err)
	}
}

func TestScanErrors(t *testing.T) {
	cases := [][]string{
		{"scan"}, // missing required --input
		{"scan", "-i", fixturesDir + "/vulnerable.yaml", "-p", "bogus"},
		{"scan", "-i", fixturesDir + "/vulnerable.yaml", "-f", "xml"},
		{"scan", "-i", fixturesDir + "/does-not-exist.yaml"},
		{"scan", "--live", "--watch"}, // watch is unsupported with live
	}
	for _, args := range cases {
		if _, err := runCLI(t, args...); err == nil {
			t.Errorf("expected error for args %v", args)
		}
	}
}
