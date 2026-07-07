package waiver

import (
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func mustParse(t *testing.T, y string) *Set {
	t.Helper()
	s, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func now() time.Time { return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) }

var priv = api.Finding{ID: "KG-001", Title: "Privileged container", Severity: api.SeverityCritical,
	Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}}

func TestMatchByIDWildcardResource(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: KG-001
    justification: compensating control X
    expires: "2026-12-31T00:00:00Z"
`)
	if _, ok := s.Match(priv, now()); !ok {
		t.Fatal("id-only waiver should match any resource for that check")
	}
	// A different check id is not covered.
	other := priv
	other.ID = "KG-002"
	if _, ok := s.Match(other, now()); ok {
		t.Fatal("waiver must not cover a different check id")
	}
}

func TestMatchByResourceSelector(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: KG-001
    resource: { kind: Deployment, namespace: payments, name: checkout }
    justification: known risk
    expires: "2026-12-31T00:00:00Z"
`)
	if _, ok := s.Match(priv, now()); !ok {
		t.Fatal("exact resource selector should match")
	}
	// Same check, different resource → not covered.
	elsewhere := priv
	elsewhere.Resource.Name = "other"
	if _, ok := s.Match(elsewhere, now()); ok {
		t.Fatal("selector must not match a different resource")
	}
}

func TestExpiredWaiverDoesNotApply(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: KG-001
    justification: temporary
    expires: "2026-06-01T00:00:00Z"
`)
	if _, ok := s.Match(priv, now()); ok {
		t.Fatal("expired waiver must not apply (finding re-blocks)")
	}
}

func TestPartition(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: KG-001
    justification: x
    expires: "2026-12-31T00:00:00Z"
`)
	findings := []api.Finding{priv, {ID: "KG-013", Severity: api.SeverityHigh, Resource: api.ResourceRef{Kind: "ClusterRole", Name: "power"}}}
	blocking, waived := s.Partition(findings, now())
	if len(blocking) != 1 || blocking[0].ID != "KG-013" {
		t.Fatalf("blocking: %+v", blocking)
	}
	if len(waived) != 1 || waived[0].Finding.ID != "KG-001" || waived[0].Entry.Justification != "x" {
		t.Fatalf("waived: %+v", waived)
	}
}

func TestStrictAndValidation(t *testing.T) {
	// Unknown key rejected.
	if _, err := Parse([]byte("waivers:\n  - id: KG-001\n    bogus: 1\n    justification: x\n    expires: \"2026-12-31T00:00:00Z\"\n")); err == nil {
		t.Fatal("unknown key should be rejected (strict)")
	}
	// Missing justification.
	if _, err := Parse([]byte("waivers:\n  - id: KG-001\n    expires: \"2026-12-31T00:00:00Z\"\n")); err == nil {
		t.Fatal("missing justification should be rejected")
	}
	// Missing/invalid expiry.
	if _, err := Parse([]byte("waivers:\n  - id: KG-001\n    justification: x\n")); err == nil {
		t.Fatal("missing expires should be rejected")
	}
	if _, err := Parse([]byte("waivers:\n  - id: KG-001\n    justification: x\n    expires: not-a-date\n")); err == nil {
		t.Fatal("bad expires should be rejected")
	}
	// Empty set is valid and nil-safe.
	empty := mustParse(t, "waivers: []\n")
	if !empty.Empty() {
		t.Fatal("empty set should report Empty()")
	}
	var nilSet *Set
	if !nilSet.Empty() {
		t.Fatal("nil set should report Empty()")
	}
	if _, ok := nilSet.Match(priv, now()); ok {
		t.Fatal("nil set should never match")
	}
}
