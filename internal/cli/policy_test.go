package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func TestScanWithCustomPolicy(t *testing.T) {
	out, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml",
		"--policy", "../../examples/policies/example-policies.yaml", "-f", "json")
	if err != nil {
		t.Fatalf("scan with policy: %v", err)
	}
	var rep api.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	var sawCustom bool
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, "ORG-") {
			sawCustom = true
		}
	}
	if !sawCustom {
		t.Fatal("expected a custom ORG-* finding from the policy pack")
	}
}

func TestScanCustomPolicyGate(t *testing.T) {
	// A custom high-severity policy trips --fail-on high alongside the built-ins.
	pf := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(pf, []byte(`apiVersion: kubeguard.io/policy/v1
policies:
  - id: ORG-X
    title: "no root"
    severity: high
    category: workload-hardening
    target: container
    match: 'container.runAsUser == 0'
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// hardened has no root container, so a hardened scan with ONLY this custom
	// policy and --fail-on high must pass (proving the custom finding is what gates).
	if _, err := runCLI(t, "scan", "-i", fixturesDir+"/hardened.yaml", "--policy", pf, "--fail-on", "high"); err != nil {
		t.Errorf("hardened + custom policy should pass the gate, got %v", err)
	}
}

func TestScanBadPolicyRejected(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(pf, []byte("apiVersion: kubeguard.io/policy/v1\npolicies: [{id: A, title: t, severity: high, category: c, match: \"1 + 1\"}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "--policy", pf); err == nil {
		t.Fatal("a malformed policy pack should fail the scan")
	}
}
