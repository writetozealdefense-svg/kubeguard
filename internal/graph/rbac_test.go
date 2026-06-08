package graph

import (
	"testing"

	"github.com/kubeguard/kubeguard/internal/model"
)

// --- rule predicates ------------------------------------------------------

func TestRuleWildcardPredicates(t *testing.T) {
	tests := []struct {
		name         string
		rule         model.PolicyRule
		fullWildcard bool
		anyWildcard  bool
	}{
		{
			name:         "full wildcard",
			rule:         model.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			fullWildcard: true,
			anyWildcard:  true,
		},
		{
			name:         "verb wildcard only",
			rule:         model.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}},
			fullWildcard: false,
			anyWildcard:  true,
		},
		{
			name:         "resource wildcard only",
			rule:         model.PolicyRule{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
			fullWildcard: false,
			anyWildcard:  true,
		},
		{
			name:         "apigroup wildcard only",
			rule:         model.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			fullWildcard: false,
			anyWildcard:  true,
		},
		{
			name:         "no wildcard",
			rule:         model.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			fullWildcard: false,
			anyWildcard:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuleFullWildcard(tt.rule); got != tt.fullWildcard {
				t.Errorf("RuleFullWildcard = %v, want %v", got, tt.fullWildcard)
			}
			if got := RuleAnyWildcard(tt.rule); got != tt.anyWildcard {
				t.Errorf("RuleAnyWildcard = %v, want %v", got, tt.anyWildcard)
			}
		})
	}
}

func TestRuleGrantsSecrets(t *testing.T) {
	tests := []struct {
		name string
		rule model.PolicyRule
		want bool
	}{
		{"secrets get", model.PolicyRule{Resources: []string{"secrets"}, Verbs: []string{"get"}}, true},
		{"secrets list", model.PolicyRule{Resources: []string{"secrets"}, Verbs: []string{"list"}}, true},
		{"secrets watch", model.PolicyRule{Resources: []string{"secrets"}, Verbs: []string{"watch"}}, true},
		{"wildcard resource get", model.PolicyRule{Resources: []string{"*"}, Verbs: []string{"get"}}, true},
		{"secrets wildcard verb", model.PolicyRule{Resources: []string{"secrets"}, Verbs: []string{"*"}}, true},
		{"secrets create only", model.PolicyRule{Resources: []string{"secrets"}, Verbs: []string{"create"}}, false},
		{"pods get", model.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"get"}}, false},
		{"empty", model.PolicyRule{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuleGrantsSecrets(tt.rule); got != tt.want {
				t.Errorf("RuleGrantsSecrets = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleGrantsPodCreate(t *testing.T) {
	tests := []struct {
		name string
		rule model.PolicyRule
		want bool
	}{
		{"pods create", model.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"create"}}, true},
		{"wildcard resource create", model.PolicyRule{Resources: []string{"*"}, Verbs: []string{"create"}}, true},
		{"pods wildcard verb", model.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"*"}}, true},
		{"pods/exec", model.PolicyRule{Resources: []string{"pods/exec"}, Verbs: []string{"create"}}, true},
		{"pods/attach", model.PolicyRule{Resources: []string{"pods/attach"}, Verbs: []string{"get"}}, true},
		{"pods get only", model.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"get"}}, false},
		{"deployments create", model.PolicyRule{Resources: []string{"deployments"}, Verbs: []string{"create"}}, false},
		{"empty", model.PolicyRule{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuleGrantsPodCreate(tt.rule); got != tt.want {
				t.Errorf("RuleGrantsPodCreate = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- SA capability helpers ------------------------------------------------

// rbacGraph builds a graph from RBAC resources expressed directly as typed
// values, bypassing JSON normalization so the SA-capability logic is exercised
// in isolation.
func rbacGraph(roles []model.Role, clusterRoles []model.ClusterRole, rbs []model.RoleBinding, crbs []model.ClusterRoleBinding) *Graph {
	return &Graph{
		Roles:               roles,
		ClusterRoles:        clusterRoles,
		RoleBindings:        rbs,
		ClusterRoleBindings: crbs,
	}
}

func saSubject(ns, name string) model.Subject {
	return model.Subject{Kind: "ServiceAccount", Name: name, Namespace: ns}
}

func TestSAIsClusterAdmin(t *testing.T) {
	t.Run("bound to cluster-admin by name (unresolved object)", func(t *testing.T) {
		g := rbacGraph(nil, nil, nil, []model.ClusterRoleBinding{{
			RoleRef:  model.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []model.Subject{saSubject("team", "admin-sa")},
		}})
		if !g.SAIsClusterAdmin("team", "admin-sa") {
			t.Error("expected admin-sa to be cluster-admin")
		}
	})

	t.Run("bound to full-wildcard role", func(t *testing.T) {
		g := rbacGraph(nil,
			[]model.ClusterRole{{
				Resource: model.Resource{Name: "god"},
				Rules:    []model.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			}},
			nil,
			[]model.ClusterRoleBinding{{
				RoleRef:  model.RoleRef{Kind: "ClusterRole", Name: "god"},
				Subjects: []model.Subject{saSubject("team", "wild-sa")},
			}})
		if !g.SAIsClusterAdmin("team", "wild-sa") {
			t.Error("expected wild-sa to be cluster-admin via wildcard role")
		}
	})

	t.Run("limited role is not cluster-admin", func(t *testing.T) {
		g := rbacGraph(
			[]model.Role{{
				Resource: model.Resource{Name: "reader", Namespace: "team"},
				Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}},
			nil,
			[]model.RoleBinding{{
				Resource: model.Resource{Namespace: "team"},
				RoleRef:  model.RoleRef{Kind: "Role", Name: "reader"},
				Subjects: []model.Subject{saSubject("team", "reader-sa")},
			}},
			nil)
		if g.SAIsClusterAdmin("team", "reader-sa") {
			t.Error("reader-sa should not be cluster-admin")
		}
	})

	t.Run("unbound SA is not cluster-admin", func(t *testing.T) {
		g := rbacGraph(nil, nil, nil, nil)
		if g.SAIsClusterAdmin("team", "ghost") {
			t.Error("unbound SA must not be cluster-admin")
		}
	})
}

func TestSACanReadSecrets(t *testing.T) {
	t.Run("explicit secrets role", func(t *testing.T) {
		g := rbacGraph(
			[]model.Role{{
				Resource: model.Resource{Name: "secret-reader", Namespace: "team"},
				Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}},
			}},
			nil,
			[]model.RoleBinding{{
				Resource: model.Resource{Namespace: "team"},
				RoleRef:  model.RoleRef{Kind: "Role", Name: "secret-reader"},
				Subjects: []model.Subject{saSubject("team", "sr-sa")},
			}},
			nil)
		if !g.SACanReadSecrets("team", "sr-sa") {
			t.Error("sr-sa should read secrets")
		}
		if g.SACanCreatePods("team", "sr-sa") {
			t.Error("sr-sa should not create pods")
		}
	})

	t.Run("cluster-admin implicit wildcard reads secrets", func(t *testing.T) {
		g := rbacGraph(nil, nil, nil, []model.ClusterRoleBinding{{
			RoleRef:  model.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []model.Subject{saSubject("team", "admin-sa")},
		}})
		if !g.SACanReadSecrets("team", "admin-sa") {
			t.Error("cluster-admin SA should read secrets via implicit wildcard")
		}
		if !g.SACanCreatePods("team", "admin-sa") {
			t.Error("cluster-admin SA should create pods via implicit wildcard")
		}
	})

	t.Run("pod reader cannot read secrets", func(t *testing.T) {
		g := rbacGraph(
			[]model.Role{{
				Resource: model.Resource{Name: "pod-reader", Namespace: "team"},
				Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			}},
			nil,
			[]model.RoleBinding{{
				Resource: model.Resource{Namespace: "team"},
				RoleRef:  model.RoleRef{Kind: "Role", Name: "pod-reader"},
				Subjects: []model.Subject{saSubject("team", "pr-sa")},
			}},
			nil)
		if g.SACanReadSecrets("team", "pr-sa") {
			t.Error("pr-sa should not read secrets")
		}
	})
}

func TestSACanCreatePods(t *testing.T) {
	g := rbacGraph(
		[]model.Role{{
			Resource: model.Resource{Name: "pod-exec", Namespace: "team"},
			Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
		}},
		nil,
		[]model.RoleBinding{{
			Resource: model.Resource{Namespace: "team"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "pod-exec"},
			Subjects: []model.Subject{saSubject("team", "exec-sa")},
		}},
		nil)
	if !g.SACanCreatePods("team", "exec-sa") {
		t.Error("exec-sa should be able to create/exec pods")
	}
	if g.SACanCreatePods("team", "nobody") {
		t.Error("unbound SA should not create pods")
	}
}
