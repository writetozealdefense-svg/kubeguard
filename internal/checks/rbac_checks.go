package checks

import (
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// Rule predicates live in the graph package so the checks and attack engines
// share one implementation (graph.RuleFullWildcard, graph.RuleGrantsSecrets, …).

func findRoleRules(g *graph.Graph, kind, name string) ([]model.PolicyRule, bool) {
	switch kind {
	case "ClusterRole":
		for _, cr := range g.ClusterRoles {
			if cr.Name == name {
				return cr.Rules, true
			}
		}
	case "Role":
		for _, r := range g.Roles {
			if r.Name == name {
				return r.Rules, true
			}
		}
	}
	return nil, false
}

func hasPrivSubject(subjects []model.Subject) bool {
	for _, s := range subjects {
		if s.Kind == "ServiceAccount" || s.Kind == "Group" {
			return true
		}
	}
	return false
}

func allRoles(g *graph.Graph) []model.Resource {
	out := make([]model.Resource, 0, len(g.Roles)+len(g.ClusterRoles))
	for _, r := range g.Roles {
		out = append(out, r.Resource)
	}
	for _, cr := range g.ClusterRoles {
		out = append(out, cr.Resource)
	}
	return out
}

func rulesOf(g *graph.Graph, r model.Resource) []model.PolicyRule {
	rules, _ := findRoleRules(g, r.Kind, r.Name)
	return rules
}

// --- KG-011: cluster-admin / wildcard binding to a SA or group ------------

type clusterAdminBindingCheck struct{}

func (clusterAdminBindingCheck) Meta() Meta {
	return Meta{
		ID: "KG-011", Title: "Binding grants cluster-admin to a ServiceAccount or group",
		Severity: api.SeverityCritical, Category: catRBAC,
		Grants:      []api.Capability{api.CapClusterAdmin},
		Refs:        []api.ControlRef{cis("5.1.1"), nsa("RBAC"), attack("T1078")},
		Remediation: "Bind a least-privilege Role instead of cluster-admin or a wildcard ClusterRole.",
	}
}

func (m clusterAdminBindingCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	check := func(r model.Resource, rr model.RoleRef, subs []model.Subject) {
		if !hasPrivSubject(subs) {
			return
		}
		if reason, ok := adminReason(g, rr); ok {
			out = append(out, m.Meta().finding(ref(r), ev("roleRef", reason)))
		}
	}
	for _, b := range g.ClusterRoleBindings {
		check(b.Resource, b.RoleRef, b.Subjects)
	}
	for _, b := range g.RoleBindings {
		check(b.Resource, b.RoleRef, b.Subjects)
	}
	return out
}

func adminReason(g *graph.Graph, rr model.RoleRef) (string, bool) {
	if rr.Kind == "ClusterRole" && rr.Name == "cluster-admin" {
		return "cluster-admin", true
	}
	if rules, ok := findRoleRules(g, rr.Kind, rr.Name); ok {
		for _, r := range rules {
			if graph.RuleFullWildcard(r) {
				return "wildcard " + rr.Kind + " " + rr.Name, true
			}
		}
	}
	return "", false
}

// --- KG-012: wildcard RBAC rule -------------------------------------------

type wildcardRBACCheck struct{}

func (wildcardRBACCheck) Meta() Meta {
	return Meta{
		ID: "KG-012", Title: "Wildcard RBAC rule", Severity: api.SeverityHigh, Category: catRBAC,
		Grants:      []api.Capability{api.CapBroadAPIAccess},
		Refs:        []api.ControlRef{cis("5.1.3"), nsa("RBAC")},
		Remediation: "Replace wildcard apiGroups/resources/verbs with the specific values required.",
	}
}

func (m wildcardRBACCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, r := range allRoles(g) {
		for _, rule := range rulesOf(g, r) {
			if graph.RuleAnyWildcard(rule) {
				out = append(out, m.Meta().finding(ref(r), ev("rules[].verbs|resources|apiGroups", "*")))
				break
			}
		}
	}
	return out
}

// --- KG-013: secrets read -------------------------------------------------

type secretsAccessCheck struct{}

func (secretsAccessCheck) Meta() Meta {
	return Meta{
		ID: "KG-013", Title: "RBAC allows reading Secrets", Severity: api.SeverityHigh, Category: catRBAC,
		Grants:      []api.Capability{api.CapSecretRead},
		Refs:        []api.ControlRef{cis("5.1.2"), nsa("RBAC"), attack("T1552")},
		Remediation: "Remove get/list/watch on secrets; scope to named resourceNames if unavoidable.",
	}
}

func (m secretsAccessCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, r := range allRoles(g) {
		for _, rule := range rulesOf(g, r) {
			if graph.RuleGrantsSecrets(rule) {
				out = append(out, m.Meta().finding(ref(r), ev("rules[]", "get/list/watch on secrets")))
				break
			}
		}
	}
	return out
}

// --- KG-014: pod create / exec --------------------------------------------

type podCreateCheck struct{}

func (podCreateCheck) Meta() Meta {
	return Meta{
		ID: "KG-014", Title: "RBAC allows creating or exec-ing into pods", Severity: api.SeverityHigh,
		Category: catRBAC, Grants: []api.Capability{api.CapPodCreate},
		Refs:        []api.ControlRef{cis("5.1.4"), nsa("RBAC"), attack("T1610")},
		Remediation: "Remove create on pods and access to pods/exec & pods/attach.",
	}
}

func (m podCreateCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, r := range allRoles(g) {
		for _, rule := range rulesOf(g, r) {
			if graph.RuleGrantsPodCreate(rule) {
				out = append(out, m.Meta().finding(ref(r), ev("rules[]", "create pods / pods exec")))
				break
			}
		}
	}
	return out
}
