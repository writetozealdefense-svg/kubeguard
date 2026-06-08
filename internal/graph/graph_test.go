package graph

import (
	"path/filepath"
	"testing"

	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
)

const fixturesDir = "../../test/fixtures"

func load(t *testing.T, file string) *Graph {
	t.Helper()
	rs, err := offline.Load(filepath.Join(fixturesDir, file))
	if err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
	return Build(rs)
}

func TestWorkloadCount(t *testing.T) {
	for _, f := range []string{"vulnerable.yaml", "partially-hardened.yaml", "hardened.yaml"} {
		g := load(t, f)
		if len(g.Workloads) != 1 {
			t.Errorf("%s: workload count = %d, want 1", f, len(g.Workloads))
		}
	}
}

func TestCheckoutSAResolvesToClusterAdminAndSecretsPods(t *testing.T) {
	g := load(t, "vulnerable.yaml")
	granted := g.GrantedRolesForSA("payments", "checkout-sa")
	if len(granted) == 0 {
		t.Fatal("checkout-sa resolved no roles")
	}

	if !boundToClusterAdmin(granted) {
		t.Error("checkout-sa not resolved to a cluster-admin binding")
	}
	if !rulesGrantResource(granted, "secrets") {
		t.Error("checkout-sa roles do not grant access to secrets")
	}
	if !rulesGrantResource(granted, "pods") {
		t.Error("checkout-sa roles do not grant access to pods")
	}
}

func TestCheckoutLBMapsToCheckoutWorkload(t *testing.T) {
	g := load(t, "vulnerable.yaml")
	var lb model.Service
	found := false
	for _, s := range g.Services {
		if s.Name == "checkout-lb" {
			lb, found = s, true
		}
	}
	if !found {
		t.Fatal("checkout-lb service not loaded")
	}
	if lb.Type != "LoadBalancer" {
		t.Errorf("checkout-lb type = %q, want LoadBalancer", lb.Type)
	}
	workloads := g.WorkloadsForService(lb)
	if len(workloads) != 1 || workloads[0].Name != "checkout" {
		t.Fatalf("checkout-lb maps to %v, want [checkout]", names(workloads))
	}
}

func TestVulnerableWorkloadNormalization(t *testing.T) {
	g := load(t, "vulnerable.yaml")
	w := g.Workloads[0]
	if w.ServiceAccountName != "checkout-sa" {
		t.Errorf("SA = %q, want checkout-sa", w.ServiceAccountName)
	}
	if !w.PodSpec.HostNetwork || !w.PodSpec.HostPID {
		t.Error("expected hostNetwork and hostPID true")
	}
	if w.PodSpec.AutomountSAToken != nil {
		t.Error("automountSAToken should be nil (cluster default) on vulnerable")
	}
	if !hasHostPath(w.PodSpec.Volumes, "/var/run/docker.sock") {
		t.Error("expected docker.sock hostPath volume")
	}
	c := w.PodSpec.Containers[0]
	if !c.Privileged {
		t.Error("expected privileged container")
	}
	if c.Image != "checkout:latest" {
		t.Errorf("image = %q, want checkout:latest", c.Image)
	}
	if !contains(c.CapsAdd, "SYS_ADMIN") {
		t.Error("expected SYS_ADMIN added capability")
	}
}

func TestPartiallyHardenedHasNoClusterAdminPath(t *testing.T) {
	g := load(t, "partially-hardened.yaml")
	granted := g.GrantedRolesForSA("payments-staging", "checkout-sa")
	if boundToClusterAdmin(granted) {
		t.Error("partially-hardened must not bind checkout-sa to cluster-admin")
	}
	if rulesGrantResource(granted, "secrets") || rulesGrantResource(granted, "pods") {
		t.Error("partially-hardened RBAC must not grant secrets/pods")
	}
	// Still privileged.
	if !g.Workloads[0].PodSpec.Containers[0].Privileged {
		t.Error("partially-hardened checkout should still be privileged")
	}
}

func TestHardenedGraphIsClean(t *testing.T) {
	g := load(t, "hardened.yaml")
	if !g.HasDefaultDeny("payments-prod") {
		t.Error("hardened namespace should have a default-deny NetworkPolicy")
	}
	w := g.Workloads[0]
	if w.PodSpec.AutomountSAToken == nil || *w.PodSpec.AutomountSAToken {
		t.Error("hardened workload should disable automountServiceAccountToken")
	}
	c := w.PodSpec.Containers[0]
	if c.Privileged {
		t.Error("hardened container must not be privileged")
	}
	if c.RunAsNonRoot == nil || !*c.RunAsNonRoot {
		t.Error("hardened container should runAsNonRoot")
	}
	if c.SeccompProfile != "RuntimeDefault" {
		t.Errorf("seccomp = %q, want RuntimeDefault", c.SeccompProfile)
	}
}

func TestCronJobNormalization(t *testing.T) {
	doc := []model.Resource{{
		Kind: "CronJob", Name: "report", Namespace: "x",
		Raw: map[string]any{
			"kind":     "CronJob",
			"metadata": map[string]any{"name": "report", "namespace": "x"},
			"spec": map[string]any{
				"jobTemplate": map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"metadata": map[string]any{"labels": map[string]any{"app": "report"}},
							"spec": map[string]any{
								"serviceAccountName": "report-sa",
								"containers": []any{
									map[string]any{"name": "c", "image": "report:1.0"},
								},
							},
						},
					},
				},
			},
		},
	}}
	g := Build(doc)
	if len(g.Workloads) != 1 {
		t.Fatalf("cronjob workloads = %d, want 1", len(g.Workloads))
	}
	w := g.Workloads[0]
	if w.ServiceAccountName != "report-sa" || w.PodLabels["app"] != "report" {
		t.Errorf("cronjob normalization off: sa=%q labels=%v", w.ServiceAccountName, w.PodLabels)
	}
}

// --- helpers ---

func boundToClusterAdmin(grs []GrantedRole) bool {
	for _, gr := range grs {
		if gr.RoleRef.Kind == "ClusterRole" && gr.RoleRef.Name == "cluster-admin" {
			return true
		}
	}
	return false
}

func rulesGrantResource(grs []GrantedRole, resource string) bool {
	for _, gr := range grs {
		for _, rule := range gr.Rules {
			for _, res := range rule.Resources {
				if res == resource || res == "*" {
					return true
				}
			}
		}
	}
	return false
}

func hasHostPath(vols []model.VolumeView, path string) bool {
	for _, v := range vols {
		if v.HostPath == path {
			return true
		}
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func names(ws []model.Workload) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Name
	}
	return out
}
