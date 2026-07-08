package policy

import (
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
)

func vulnerableGraph(t *testing.T) *graph.Graph {
	t.Helper()
	resources, err := offline.Load("../../test/fixtures/vulnerable.yaml")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return graph.Build(resources)
}

func mustParse(t *testing.T, y string) *Set {
	t.Helper()
	s, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

// TestCustomPolicyDetectsFixtureMisconfig: a sample policy detects a real
// misconfig in the vulnerable fixture with no recompile.
func TestCustomPolicyDetectsFixtureMisconfig(t *testing.T) {
	// checkout runs as UID 0 and pulls checkout:latest (implicit registry).
	set := mustParse(t, `
apiVersion: kubeguard.io/policy/v1
policies:
  - id: ORG-ROOT-1
    title: "No root containers"
    severity: high
    category: workload-hardening
    target: container
    match: 'container.runAsUser == 0'
  - id: ORG-REG-1
    title: "Approved registry only"
    severity: high
    category: supply-chain
    target: container
    match: '!container.image.startsWith("registry.internal/")'
  - id: ORG-LABEL-1
    title: "Team label required"
    severity: low
    category: workload-hardening
    target: workload
    match: '!("team" in workload.labels)'
`)
	findings := set.Evaluate(vulnerableGraph(t))
	got := map[string]bool{}
	for _, f := range findings {
		got[f.ID] = true
		if f.Severity == "" || f.Title == "" || f.Category == "" || len(f.Evidence) == 0 {
			t.Errorf("custom finding %s incomplete: %+v", f.ID, f)
		}
		if f.Resource.Name != "checkout" {
			t.Errorf("expected finding on checkout, got %s", f.Resource.Name)
		}
	}
	for _, id := range []string{"ORG-ROOT-1", "ORG-REG-1", "ORG-LABEL-1"} {
		if !got[id] {
			t.Errorf("policy %s should have fired on the vulnerable fixture", id)
		}
	}
}

func TestShippedExamplePackLoads(t *testing.T) {
	set, err := Load("../../examples/policies/example-policies.yaml")
	if err != nil {
		t.Fatalf("shipped example pack must load: %v", err)
	}
	if set.Len() != 3 {
		t.Fatalf("example pack: want 3 policies, got %d", set.Len())
	}
	// And it fires on the vulnerable fixture.
	if len(set.Evaluate(vulnerableGraph(t))) == 0 {
		t.Fatal("example pack should produce findings on the vulnerable fixture")
	}
}

func TestMalformedPoliciesRejected(t *testing.T) {
	cases := map[string]string{
		"wrong apiVersion": `
apiVersion: kubeguard.io/policy/v2
policies: [{id: A, title: t, severity: high, category: c, match: "true"}]`,
		"unknown key (strict)": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: high, category: c, match: "true", bogus: 1}]`,
		"bad severity": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: spicy, category: c, match: "true"}]`,
		"missing match": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: high, category: c}]`,
		"match not bool": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: high, category: c, match: "1 + 1"}]`,
		"match does not compile": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: high, category: c, match: "workload.nope("}]`,
		"unknown target": `
apiVersion: kubeguard.io/policy/v1
policies: [{id: A, title: t, severity: high, category: c, target: cluster, match: "true"}]`,
		"no policies": `
apiVersion: kubeguard.io/policy/v1
policies: []`,
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected a load error, got nil", name)
		}
	}
}

func TestContainerVsWorkloadScope(t *testing.T) {
	g := vulnerableGraph(t)
	// A workload-scoped policy can reach containers via workload.containers.
	wl := mustParse(t, `
apiVersion: kubeguard.io/policy/v1
policies:
  - id: W-1
    title: "host network"
    severity: high
    category: host-access
    target: workload
    match: 'workload.hostNetwork'
`)
	if len(wl.Evaluate(g)) != 1 {
		t.Fatalf("workload policy on hostNetwork should fire once, got %d", len(wl.Evaluate(g)))
	}
	// A container-scoped policy fires per matching container.
	ct := mustParse(t, `
apiVersion: kubeguard.io/policy/v1
policies:
  - id: C-1
    title: "privileged"
    severity: critical
    category: host-access
    target: container
    match: 'container.privileged'
`)
	if len(ct.Evaluate(g)) != 1 {
		t.Fatalf("container policy on privileged should fire once, got %d", len(ct.Evaluate(g)))
	}
}

// TestEvalErrorTolerated: a policy referencing a field that doesn't exist on the
// projected object evaluates to no-match rather than crashing the scan.
func TestEvalErrorTolerated(t *testing.T) {
	set := mustParse(t, `
apiVersion: kubeguard.io/policy/v1
policies:
  - id: E-1
    title: "missing field"
    severity: low
    category: c
    target: workload
    match: 'workload.doesNotExist == "x"'
`)
	// Should not panic; produces no findings (the field is absent).
	if fs := set.Evaluate(vulnerableGraph(t)); len(fs) != 0 {
		t.Fatalf("policy referencing a missing field should not match, got %d findings", len(fs))
	}
}

func TestEmptyAndNilSet(t *testing.T) {
	var nilSet *Set
	if !nilSet.Empty() || nilSet.Len() != 0 {
		t.Fatal("nil set should be empty")
	}
	if fs := nilSet.Evaluate(vulnerableGraph(t)); fs != nil {
		t.Fatalf("nil set should evaluate to nil, got %v", fs)
	}
	if !strings.HasPrefix(apiVersion, "kubeguard.io/policy/") {
		t.Fatal("apiVersion sanity")
	}
}
