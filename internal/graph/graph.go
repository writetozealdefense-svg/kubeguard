package graph

import (
	"sort"

	"github.com/kubeguard/kubeguard/internal/model"
)

// Graph is a typed inventory of loaded resources plus resolved relationships
// (ARCHITECTURE.md §6). It is built once and queried read-only by the engines.
type Graph struct {
	Resources           []model.Resource
	Workloads           []model.Workload
	ServiceAccounts     []model.ServiceAccount
	Roles               []model.Role
	ClusterRoles        []model.ClusterRole
	RoleBindings        []model.RoleBinding
	ClusterRoleBindings []model.ClusterRoleBinding
	Services            []model.Service
	NetworkPolicies     []model.NetworkPolicy
	Namespaces          []string
}

// Build constructs a Graph from loaded resources, normalizing each into its
// typed view.
func Build(resources []model.Resource) *Graph {
	g := &Graph{Resources: resources}
	nsSet := map[string]struct{}{}

	for _, r := range resources {
		if r.Namespace != "" {
			nsSet[r.Namespace] = struct{}{}
		}
		switch {
		case isWorkloadKind(r.Kind):
			if w, ok := toWorkload(r); ok {
				g.Workloads = append(g.Workloads, w)
			}
		case r.Kind == "ServiceAccount":
			g.ServiceAccounts = append(g.ServiceAccounts, toServiceAccount(r))
		case r.Kind == "Role":
			g.Roles = append(g.Roles, model.Role{Resource: r, Rules: toRules(r)})
		case r.Kind == "ClusterRole":
			g.ClusterRoles = append(g.ClusterRoles, model.ClusterRole{Resource: r, Rules: toRules(r)})
		case r.Kind == "RoleBinding":
			ref, subs := toBinding(r)
			g.RoleBindings = append(g.RoleBindings, model.RoleBinding{Resource: r, RoleRef: ref, Subjects: subs})
		case r.Kind == "ClusterRoleBinding":
			ref, subs := toBinding(r)
			g.ClusterRoleBindings = append(g.ClusterRoleBindings, model.ClusterRoleBinding{Resource: r, RoleRef: ref, Subjects: subs})
		case r.Kind == "Service":
			g.Services = append(g.Services, toService(r))
		case r.Kind == "NetworkPolicy":
			g.NetworkPolicies = append(g.NetworkPolicies, toNetworkPolicy(r))
		case r.Kind == "Namespace":
			nsSet[r.Name] = struct{}{}
		}
	}

	for ns := range nsSet {
		g.Namespaces = append(g.Namespaces, ns)
	}
	sort.Strings(g.Namespaces)
	return g
}
