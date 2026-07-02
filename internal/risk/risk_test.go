package risk

import (
	"reflect"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// chainReport models the vulnerable fixture's cluster-admin chain: an
// internet-fronted privileged pod whose escape leads through an SA token to
// cluster-admin, plus a couple of unrelated low findings.
func chainReport() api.Report {
	return api.Report{
		Findings: []api.Finding{
			{ID: "KG-018", Title: "LoadBalancer exposure", Severity: api.SeverityHigh,
				Resource: api.ResourceRef{Kind: "Service", Namespace: "payments", Name: "checkout-lb"}},
			{ID: "KG-001", Title: "Privileged container", Severity: api.SeverityCritical,
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}},
			{ID: "KG-011", Title: "Binding grants cluster-admin", Severity: api.SeverityCritical,
				Resource: api.ResourceRef{Kind: "ClusterRoleBinding", Name: "checkout-admin"}},
			{ID: "KG-019", Title: "Mutable image tag", Severity: api.SeverityLow,
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}},
			{ID: "KG-009", Title: "Writable root FS", Severity: api.SeverityLow,
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}},
		},
		Paths: []api.AttackPath{{
			ID: "AP-001", Severity: api.SeverityCritical,
			Hops: []api.PathHop{
				{Order: 1, From: api.CapInternetIngress, To: api.CapNetworkReachable, EnabledBy: "KG-018"},
				{Order: 2, From: api.CapNetworkReachable, To: api.CapContainerEscape, EnabledBy: "KG-001"},
				{Order: 3, From: api.CapContainerEscape, To: api.CapNodeAccess, EnabledBy: "KG-002"},
				{Order: 4, From: api.CapNodeAccess, To: api.CapServiceAccountToken, EnabledBy: "KG-015"},
				{Order: 5, From: api.CapServiceAccountToken, To: api.CapClusterAdmin, EnabledBy: "KG-011"},
			},
		}},
	}
}

func TestChainEnablersRankAtTop(t *testing.T) {
	scores := Score(chainReport())
	if len(scores) != 5 {
		t.Fatalf("want 5 scores, got %d", len(scores))
	}
	// The two critical chain enablers (KG-001, KG-011) must outrank the two low
	// findings on the same resource that enable nothing.
	top := map[string]bool{scores[0].FindingID: true, scores[1].FindingID: true, scores[2].FindingID: true}
	if !top["KG-001"] || !top["KG-011"] {
		t.Fatalf("chain enablers not in top 3: got order %v", ids(scores))
	}
	// The low, non-enabling findings must be last.
	last := scores[len(scores)-1].FindingID
	if last != "KG-009" && last != "KG-019" {
		t.Fatalf("expected a low non-enabler last, got %s (order %v)", last, ids(scores))
	}
	// A chain enabler must outscore a non-enabler of the same severity would-be:
	// KG-001 (critical, internet+cluster-admin path) must beat KG-019 (low).
	if scoreOf(scores, "KG-001") <= scoreOf(scores, "KG-019") {
		t.Fatalf("KG-001 should outscore KG-019")
	}
}

func TestScoreIsExplainableAndDeterministic(t *testing.T) {
	rep := chainReport()
	first := Score(rep)
	second := Score(rep)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("risk scoring is not reproducible run-to-run")
	}
	// Every score's points equal the sum of its factors — no hidden term.
	for _, rs := range first {
		sum := 0
		for _, f := range rs.Factors {
			sum += f.Points
		}
		if sum != rs.Score {
			t.Fatalf("%s: factors sum to %d but score is %d (hidden term?)", rs.FindingID, sum, rs.Score)
		}
		if len(rs.Factors) == 0 {
			t.Fatalf("%s has a score with no explaining factors", rs.FindingID)
		}
	}
	// KG-011 reaches cluster-admin via an internet path: it must carry the
	// internet-exposed and blast-radius(cluster-admin) factors.
	kg011 := factorsOf(first, "KG-011")
	if kg011["internet-exposed"] == 0 || kg011["blast-radius"] != pointsClusterAdmin {
		t.Fatalf("KG-011 factors missing internet/cluster-admin blast radius: %+v", kg011)
	}
}

func TestBreadthBonusForMultiWorkloadCheck(t *testing.T) {
	rep := api.Report{Findings: []api.Finding{
		{ID: "KG-010", Severity: api.SeverityLow, Resource: api.ResourceRef{Kind: "Deployment", Name: "a"}},
		{ID: "KG-010", Severity: api.SeverityLow, Resource: api.ResourceRef{Kind: "Deployment", Name: "b"}},
		{ID: "KG-010", Severity: api.SeverityLow, Resource: api.ResourceRef{Kind: "Deployment", Name: "c"}},
	}}
	scores := Score(rep)
	// Each KG-010 instance is affected across 3 workloads → breadth bonus present.
	if factorsOf(scores, "KG-010")["breadth"] == 0 {
		t.Fatalf("expected a breadth factor for a check firing on 3 workloads: %+v", scores[0].Factors)
	}
}

func ids(s []api.RiskScore) []string {
	out := make([]string, len(s))
	for i, r := range s {
		out[i] = r.FindingID
	}
	return out
}

func scoreOf(s []api.RiskScore, id string) int {
	for _, r := range s {
		if r.FindingID == id {
			return r.Score
		}
	}
	return -1
}

func factorsOf(s []api.RiskScore, id string) map[string]int {
	for _, r := range s {
		if r.FindingID == id {
			m := map[string]int{}
			for _, f := range r.Factors {
				m[f.Name] = f.Points
			}
			return m
		}
	}
	return nil
}
