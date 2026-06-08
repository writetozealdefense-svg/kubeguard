package graph

import "github.com/kubeguard/kubeguard/internal/model"

// GrantedRole records a role a ServiceAccount is granted via a binding. Rules
// is populated only when the referenced Role/ClusterRole object is present in
// the loaded set (Resolved). Bindings to built-in roles not in the set (e.g.
// cluster-admin) still appear with Resolved=false and the RoleRef name intact.
type GrantedRole struct {
	RoleRef     model.RoleRef
	BindingName string
	Resolved    bool
	Rules       []model.PolicyRule
}

// GrantedRolesForSA returns every role granted to the given ServiceAccount via
// RoleBindings and ClusterRoleBindings (ARCHITECTURE.md §6).
func (g *Graph) GrantedRolesForSA(namespace, name string) []GrantedRole {
	var out []GrantedRole
	for _, b := range g.ClusterRoleBindings {
		if subjectsInclude(b.Subjects, namespace, name, "") {
			out = append(out, g.resolveRef(b.RoleRef, b.Name))
		}
	}
	for _, b := range g.RoleBindings {
		if subjectsInclude(b.Subjects, namespace, name, b.Namespace) {
			out = append(out, g.resolveRef(b.RoleRef, b.Name))
		}
	}
	return out
}

// subjectsInclude reports whether subjects names the SA namespace/name. For
// RoleBindings a subject with no namespace defaults to the binding namespace.
func subjectsInclude(subjects []model.Subject, ns, name, bindingNS string) bool {
	for _, s := range subjects {
		if s.Kind != "ServiceAccount" || s.Name != name {
			continue
		}
		subNS := s.Namespace
		if subNS == "" {
			subNS = bindingNS
		}
		if subNS == ns {
			return true
		}
	}
	return false
}

func (g *Graph) resolveRef(ref model.RoleRef, bindingName string) GrantedRole {
	gr := GrantedRole{RoleRef: ref, BindingName: bindingName}
	switch ref.Kind {
	case "ClusterRole":
		for _, cr := range g.ClusterRoles {
			if cr.Name == ref.Name {
				gr.Resolved = true
				gr.Rules = cr.Rules
				return gr
			}
		}
	case "Role":
		for _, r := range g.Roles {
			if r.Name == ref.Name {
				gr.Resolved = true
				gr.Rules = r.Rules
				return gr
			}
		}
	}
	return gr
}

// WorkloadsForService returns workloads in the service's namespace whose pod
// labels match the service selector (ARCHITECTURE.md §6).
func (g *Graph) WorkloadsForService(svc model.Service) []model.Workload {
	var out []model.Workload
	if len(svc.Selector) == 0 {
		return out
	}
	for _, w := range g.Workloads {
		if w.Namespace == svc.Namespace && selectorMatches(svc.Selector, w.PodLabels) {
			out = append(out, w)
		}
	}
	return out
}

func selectorMatches(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ServiceAccountByName looks up a ServiceAccount by namespace and name.
func (g *Graph) ServiceAccountByName(namespace, name string) (model.ServiceAccount, bool) {
	for _, sa := range g.ServiceAccounts {
		if sa.Namespace == namespace && sa.Name == name {
			return sa, true
		}
	}
	return model.ServiceAccount{}, false
}

// NetworkPoliciesInNamespace returns the policies defined in a namespace.
func (g *Graph) NetworkPoliciesInNamespace(namespace string) []model.NetworkPolicy {
	var out []model.NetworkPolicy
	for _, np := range g.NetworkPolicies {
		if np.Namespace == namespace {
			out = append(out, np)
		}
	}
	return out
}

// HasDefaultDeny reports whether a namespace has a default-deny NetworkPolicy.
func (g *Graph) HasDefaultDeny(namespace string) bool {
	for _, np := range g.NetworkPoliciesInNamespace(namespace) {
		if np.IsDefaultDeny() {
			return true
		}
	}
	return false
}
