package checks

import (
	"sort"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/pkg/api"
)

type networkPolicyCheck struct{}

func (networkPolicyCheck) Meta() Meta {
	return Meta{
		ID: "KG-017", Title: "Namespace has no default-deny NetworkPolicy", Severity: api.SeverityMedium,
		Category: catNetwork, Grants: []api.Capability{api.CapLateralMovement},
		Refs:        []api.ControlRef{cis("5.3.2"), nsa("Network separation")},
		Remediation: "Apply a default-deny NetworkPolicy (empty podSelector, Ingress+Egress) and allow only required flows.",
	}
}

func (m networkPolicyCheck) Run(g *graph.Graph) []api.Finding {
	// Only namespaces that actually run workloads are at risk.
	withWorkloads := map[string]bool{}
	for _, w := range g.Workloads {
		if w.Namespace != "" {
			withWorkloads[w.Namespace] = true
		}
	}
	namespaces := make([]string, 0, len(withWorkloads))
	for ns := range withWorkloads {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	var out []api.Finding
	for _, ns := range namespaces {
		if !g.HasDefaultDeny(ns) {
			out = append(out, m.Meta().finding(nsRef(ns), ev("networkpolicies", "no default-deny in namespace")))
		}
	}
	return out
}
