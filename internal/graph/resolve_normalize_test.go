package graph

import (
	"testing"

	"github.com/kubeguard/kubeguard/internal/model"
)

// workloadResource builds a minimal workload Resource of the given kind with a
// pod template carrying the given SA name and pod labels.
func workloadResource(kind, name, ns, saName string, labels map[string]string, replicas *int) model.Resource {
	podSpec := map[string]any{
		"serviceAccountName": saName,
		"containers": []any{
			map[string]any{"name": "c", "image": "img:1.0"},
		},
	}
	tmpl := map[string]any{
		"metadata": map[string]any{"labels": toAnyMap(labels)},
		"spec":     podSpec,
	}

	var raw map[string]any
	switch kind {
	case "Pod":
		raw = map[string]any{
			"kind":     "Pod",
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": toAnyMap(labels)},
			"spec":     podSpec,
		}
	case "CronJob":
		raw = map[string]any{
			"kind":     "CronJob",
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec": map[string]any{
				"jobTemplate": map[string]any{
					"spec": map[string]any{"template": tmpl},
				},
			},
		}
	default: // Deployment, StatefulSet, DaemonSet, Job
		spec := map[string]any{"template": tmpl}
		if replicas != nil {
			spec["replicas"] = *replicas
		}
		raw = map[string]any{
			"kind":     kind,
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec":     spec,
		}
	}

	r := model.Resource{Kind: kind, Name: name, Namespace: ns, Raw: raw}
	if kind == "Pod" {
		r.Labels = labels
	}
	return r
}

func toAnyMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestWorkloadKindNormalization(t *testing.T) {
	three := 3
	tests := []struct {
		kind         string
		replicas     *int
		wantReplicas int
	}{
		{"Pod", nil, 1},
		{"Deployment", &three, 3},
		{"StatefulSet", &three, 3},
		{"DaemonSet", nil, 1},
		{"Job", nil, 1},
		{"CronJob", nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			labels := map[string]string{"app": "x"}
			r := workloadResource(tt.kind, "w", "ns", "w-sa", labels, tt.replicas)
			g := Build([]model.Resource{r})
			if len(g.Workloads) != 1 {
				t.Fatalf("%s workloads = %d, want 1", tt.kind, len(g.Workloads))
			}
			w := g.Workloads[0]
			if w.ServiceAccountName != "w-sa" {
				t.Errorf("SA = %q, want w-sa", w.ServiceAccountName)
			}
			if w.PodLabels["app"] != "x" {
				t.Errorf("labels = %v, want app=x", w.PodLabels)
			}
			if w.Replicas != tt.wantReplicas {
				t.Errorf("replicas = %d, want %d", w.Replicas, tt.wantReplicas)
			}
			if len(w.PodSpec.Containers) != 1 {
				t.Errorf("containers = %d, want 1", len(w.PodSpec.Containers))
			}
		})
	}
}

func TestToWorkloadDefaultsAndRejections(t *testing.T) {
	t.Run("empty SA defaults to default", func(t *testing.T) {
		r := workloadResource("Deployment", "w", "ns", "", nil, nil)
		w, ok := toWorkload(r)
		if !ok {
			t.Fatal("expected workload to normalize")
		}
		if w.ServiceAccountName != "default" {
			t.Errorf("SA = %q, want default", w.ServiceAccountName)
		}
	})

	t.Run("non-workload kind rejected", func(t *testing.T) {
		if _, ok := toWorkload(model.Resource{Kind: "ConfigMap"}); ok {
			t.Error("ConfigMap must not normalize as a workload")
		}
	})
}

func TestServiceAccountByName(t *testing.T) {
	g := &Graph{ServiceAccounts: []model.ServiceAccount{
		{Resource: model.Resource{Name: "a", Namespace: "ns1"}},
		{Resource: model.Resource{Name: "b", Namespace: "ns2"}},
	}}
	if _, ok := g.ServiceAccountByName("ns1", "a"); !ok {
		t.Error("expected to find ns1/a")
	}
	if _, ok := g.ServiceAccountByName("ns1", "b"); ok {
		t.Error("ns1/b should not be found (wrong namespace)")
	}
	if _, ok := g.ServiceAccountByName("ns3", "a"); ok {
		t.Error("ns3/a should not be found")
	}
}

func TestRoleBindingSubjectNamespaceDefaulting(t *testing.T) {
	// A subject with no explicit namespace defaults to the binding's namespace.
	g := rbacGraph(
		[]model.Role{{
			Resource: model.Resource{Name: "r", Namespace: "team"},
			Rules:    []model.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"get"}}},
		}},
		nil,
		[]model.RoleBinding{{
			Resource: model.Resource{Namespace: "team"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "r"},
			Subjects: []model.Subject{{Kind: "ServiceAccount", Name: "sa"}}, // no namespace
		}},
		nil)

	if got := g.GrantedRolesForSA("team", "sa"); len(got) != 1 {
		t.Errorf("granted roles for team/sa = %d, want 1", len(got))
	}
	// Same SA name in a different namespace must not match the defaulted subject.
	if got := g.GrantedRolesForSA("other", "sa"); len(got) != 0 {
		t.Errorf("granted roles for other/sa = %d, want 0", len(got))
	}
}

func TestGrantedRolesUnresolvedRef(t *testing.T) {
	// Binding references a Role object that is not loaded -> Resolved=false.
	g := rbacGraph(nil, nil,
		[]model.RoleBinding{{
			Resource: model.Resource{Namespace: "team"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "missing"},
			Subjects: []model.Subject{saSubject("team", "sa")},
		}},
		nil)
	granted := g.GrantedRolesForSA("team", "sa")
	if len(granted) != 1 {
		t.Fatalf("granted = %d, want 1", len(granted))
	}
	if granted[0].Resolved {
		t.Error("ref to missing Role should be unresolved")
	}
	if len(granted[0].Rules) != 0 {
		t.Error("unresolved ref should carry no rules")
	}
}

func TestSubjectsIncludeNonSAIgnored(t *testing.T) {
	g := rbacGraph(nil, nil,
		[]model.RoleBinding{{
			Resource: model.Resource{Namespace: "team"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "r"},
			Subjects: []model.Subject{
				{Kind: "User", Name: "sa", Namespace: "team"},  // wrong kind
				{Kind: "Group", Name: "sa", Namespace: "team"}, // wrong kind
			},
		}},
		nil)
	if got := g.GrantedRolesForSA("team", "sa"); len(got) != 0 {
		t.Errorf("User/Group subjects must not match SA: got %d", len(got))
	}
}

func TestWorkloadsForServiceSelector(t *testing.T) {
	g := &Graph{Workloads: []model.Workload{
		{Resource: model.Resource{Name: "match", Namespace: "ns"}, PodLabels: map[string]string{"app": "web", "tier": "fe"}},
		{Resource: model.Resource{Name: "partial", Namespace: "ns"}, PodLabels: map[string]string{"app": "web"}},
		{Resource: model.Resource{Name: "otherns", Namespace: "other"}, PodLabels: map[string]string{"app": "web", "tier": "fe"}},
	}}

	t.Run("multi-label selector matches only full superset", func(t *testing.T) {
		svc := model.Service{Resource: model.Resource{Namespace: "ns"}, Selector: map[string]string{"app": "web", "tier": "fe"}}
		got := g.WorkloadsForService(svc)
		if len(got) != 1 || got[0].Name != "match" {
			t.Fatalf("got %v, want [match]", names(got))
		}
	})

	t.Run("empty selector matches nothing", func(t *testing.T) {
		svc := model.Service{Resource: model.Resource{Namespace: "ns"}}
		if got := g.WorkloadsForService(svc); len(got) != 0 {
			t.Errorf("empty selector should match nothing, got %v", names(got))
		}
	})

	t.Run("namespace isolation", func(t *testing.T) {
		svc := model.Service{Resource: model.Resource{Namespace: "other"}, Selector: map[string]string{"app": "web", "tier": "fe"}}
		got := g.WorkloadsForService(svc)
		if len(got) != 1 || got[0].Name != "otherns" {
			t.Fatalf("got %v, want [otherns]", names(got))
		}
	})
}

func TestNetworkPolicyResolution(t *testing.T) {
	deny := model.NetworkPolicy{
		Resource:    model.Resource{Name: "default-deny", Namespace: "ns"},
		PolicyTypes: []string{"Ingress", "Egress"},
	}
	allowAll := model.NetworkPolicy{
		Resource:         model.Resource{Name: "allow", Namespace: "ns"},
		PodSelector:      map[string]string{"app": "web"},
		PolicyTypes:      []string{"Ingress"},
		IngressRuleCount: 1,
	}
	otherNS := model.NetworkPolicy{
		Resource:    model.Resource{Name: "deny2", Namespace: "other"},
		PolicyTypes: []string{"Ingress"},
	}
	g := &Graph{NetworkPolicies: []model.NetworkPolicy{deny, allowAll, otherNS}}

	if got := g.NetworkPoliciesInNamespace("ns"); len(got) != 2 {
		t.Errorf("policies in ns = %d, want 2", len(got))
	}
	if !g.HasDefaultDeny("ns") {
		t.Error("ns should have default-deny")
	}

	t.Run("namespace without default-deny", func(t *testing.T) {
		g2 := &Graph{NetworkPolicies: []model.NetworkPolicy{allowAll}}
		if g2.HasDefaultDeny("ns") {
			t.Error("ns with only an allow policy must not report default-deny")
		}
	})

	t.Run("namespace with no policies", func(t *testing.T) {
		if g.HasDefaultDeny("empty") {
			t.Error("empty namespace must not report default-deny")
		}
	})
}

func TestStringifyPort(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"string named port", "http", "http"},
		{"integer port", float64(8080), "8080"},
		{"fractional rejected", float64(80.5), ""},
		{"nil", nil, ""},
		{"unsupported type", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringifyPort(tt.in); got != tt.want {
				t.Errorf("stringifyPort(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestServiceNormalizationDefaultsAndPorts(t *testing.T) {
	r := model.Resource{
		Kind: "Service", Name: "svc", Namespace: "ns",
		Raw: map[string]any{
			"spec": map[string]any{
				"selector": map[string]any{"app": "web"},
				"ports": []any{
					map[string]any{"port": float64(80), "targetPort": float64(8080), "protocol": "TCP"},
					map[string]any{"port": float64(443), "targetPort": "https"},
				},
			},
		},
	}
	svc := toService(r)
	if svc.Type != "ClusterIP" {
		t.Errorf("default type = %q, want ClusterIP", svc.Type)
	}
	if len(svc.Ports) != 2 {
		t.Fatalf("ports = %d, want 2", len(svc.Ports))
	}
	if svc.Ports[0].TargetPort != "8080" || svc.Ports[1].TargetPort != "https" {
		t.Errorf("targetPorts = %q,%q want 8080,https", svc.Ports[0].TargetPort, svc.Ports[1].TargetPort)
	}
}
