package graph

import "github.com/kubeguard/kubeguard/internal/model"

// --- rule predicates (shared by the checks and attack engines) ------------

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasAny(ss []string, wants ...string) bool {
	for _, w := range wants {
		if has(ss, w) {
			return true
		}
	}
	return false
}

func wildcard(ss []string) bool { return has(ss, "*") }

// RuleFullWildcard reports whether a rule grants every verb on every resource
// in every API group (cluster-admin-equivalent).
func RuleFullWildcard(r model.PolicyRule) bool {
	return wildcard(r.APIGroups) && wildcard(r.Resources) && wildcard(r.Verbs)
}

// RuleAnyWildcard reports whether a rule uses a wildcard in any dimension.
func RuleAnyWildcard(r model.PolicyRule) bool {
	return wildcard(r.APIGroups) || wildcard(r.Resources) || wildcard(r.Verbs)
}

// RuleGrantsSecrets reports whether a rule allows reading Secrets.
func RuleGrantsSecrets(r model.PolicyRule) bool {
	resOK := has(r.Resources, "secrets") || wildcard(r.Resources)
	verbOK := hasAny(r.Verbs, "get", "list", "watch") || wildcard(r.Verbs)
	return resOK && verbOK
}

// RuleGrantsPodCreate reports whether a rule allows creating or exec-ing pods.
func RuleGrantsPodCreate(r model.PolicyRule) bool {
	if (has(r.Resources, "pods") || wildcard(r.Resources)) && (has(r.Verbs, "create") || wildcard(r.Verbs)) {
		return true
	}
	return has(r.Resources, "pods/exec") || has(r.Resources, "pods/attach")
}

// --- ServiceAccount capability helpers (used by the attack engine) --------

func (g *Graph) saRules(namespace, name string) []model.PolicyRule {
	var rules []model.PolicyRule
	for _, gr := range g.GrantedRolesForSA(namespace, name) {
		if gr.RoleRef.Kind == "ClusterRole" && gr.RoleRef.Name == "cluster-admin" {
			// cluster-admin's wildcard rule is implicit even when the built-in
			// ClusterRole object is absent from the loaded set.
			rules = append(rules, model.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}})
		}
		rules = append(rules, gr.Rules...)
	}
	return rules
}

// SAIsClusterAdmin reports whether the ServiceAccount is bound to cluster-admin
// or a full-wildcard role.
func (g *Graph) SAIsClusterAdmin(namespace, name string) bool {
	for _, gr := range g.GrantedRolesForSA(namespace, name) {
		if gr.RoleRef.Kind == "ClusterRole" && gr.RoleRef.Name == "cluster-admin" {
			return true
		}
		for _, r := range gr.Rules {
			if RuleFullWildcard(r) {
				return true
			}
		}
	}
	return false
}

// SACanReadSecrets reports whether the ServiceAccount can read Secrets.
func (g *Graph) SACanReadSecrets(namespace, name string) bool {
	for _, r := range g.saRules(namespace, name) {
		if RuleGrantsSecrets(r) {
			return true
		}
	}
	return false
}

// SACanCreatePods reports whether the ServiceAccount can create/exec pods.
func (g *Graph) SACanCreatePods(namespace, name string) bool {
	for _, r := range g.saRules(namespace, name) {
		if RuleGrantsPodCreate(r) {
			return true
		}
	}
	return false
}
