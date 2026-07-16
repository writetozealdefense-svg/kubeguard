package analyzer

import (
	"path/filepath"
	"testing"

	"github.com/kubeguard/kubeguard/internal/loader/offline"
)

func TestAnalyzeVulnerable(t *testing.T) {
	rs, err := offline.Load(filepath.Join("../../test/fixtures", "vulnerable.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(rs, "zeal-default", false)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(rep.Findings) == 0 || len(rep.Paths) == 0 || len(rep.Compliance) != 12 {
		t.Errorf("unexpected report: findings=%d paths=%d frameworks=%d",
			len(rep.Findings), len(rep.Paths), len(rep.Compliance))
	}
	if rep.Profile != "zeal-default" {
		t.Errorf("profile = %q", rep.Profile)
	}
	if rep.Posture.ControlsAssessed == 0 {
		t.Error("posture should assess controls")
	}
}

func TestAnalyzeHardenedClean(t *testing.T) {
	rs, _ := offline.Load(filepath.Join("../../test/fixtures", "hardened.yaml"))
	rep, err := Analyze(rs, "zeal-default", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || len(rep.Paths) != 0 {
		t.Errorf("hardened should be clean: findings=%d paths=%d", len(rep.Findings), len(rep.Paths))
	}
}

func TestAnalyzeBadProfile(t *testing.T) {
	if _, err := Analyze(nil, "nope", false); err == nil {
		t.Error("expected error for unknown profile")
	}
}
