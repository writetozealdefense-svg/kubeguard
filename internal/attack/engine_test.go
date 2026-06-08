package attack

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

const fixturesDir = "../../test/fixtures"

func loadGraph(t *testing.T, file string) *graph.Graph {
	t.Helper()
	rs, err := offline.Load(filepath.Join(fixturesDir, file))
	if err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
	return graph.Build(rs)
}

func goldenPaths(t *testing.T, name string, got []api.AttackPath) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join(fixturesDir, "golden", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(lf(b), lf(want)) {
		t.Errorf("paths differ from golden %s\n--- got ---\n%s", path, b)
	}
}

func TestVulnerableClusterAdminChain(t *testing.T) {
	paths := BuildPaths(loadGraph(t, "vulnerable.yaml"), false)
	goldenPaths(t, "vulnerable.paths.json", paths)

	if len(paths) != 1 {
		t.Fatalf("vulnerable: %d paths, want 1", len(paths))
	}
	p := paths[0]
	if p.Severity != api.SeverityCritical {
		t.Errorf("severity = %s, want critical", p.Severity)
	}

	wantPrimitives := []api.Capability{
		api.CapInternetIngress, api.CapNetworkReachable, api.CapContainerEscape,
		api.CapNodeAccess, api.CapServiceAccountToken, api.CapClusterAdmin, api.CapLateralMovement,
	}
	if got := chainCaps(p); !equalCaps(got, wantPrimitives) {
		t.Errorf("primitive chain:\n got %v\nwant %v", got, wantPrimitives)
	}

	wantTech := []string{"T1190", "T1611", "T1552.001", "T1078", "T1021"}
	if got := uniqueTechniques(p.Hops); !equalStr(got, wantTech) {
		t.Errorf("techniques:\n got %v\nwant %v", got, wantTech)
	}

	wantEnablers := []string{"KG-018", "KG-001", "KG-002", "KG-015", "KG-011", "KG-017"}
	if got := enablers(p); !equalStr(got, wantEnablers) {
		t.Errorf("enablers:\n got %v\nwant %v", got, wantEnablers)
	}
}

func TestPartiallyHardenedHostAccessOnly(t *testing.T) {
	paths := BuildPaths(loadGraph(t, "partially-hardened.yaml"), false)
	goldenPaths(t, "partially-hardened.paths.json", paths)

	if len(paths) != 1 {
		t.Fatalf("partially-hardened: %d paths, want 1", len(paths))
	}
	p := paths[0]
	if p.Severity != api.SeverityCritical {
		t.Errorf("severity = %s, want critical (host access)", p.Severity)
	}
	for _, h := range p.Hops {
		if h.To == api.CapClusterAdmin {
			t.Error("partially-hardened must not reach cluster-admin")
		}
	}
	if !reaches(p, api.CapNodeAccess) {
		t.Error("partially-hardened should reach node access (still privileged)")
	}
}

func TestHardenedNoPaths(t *testing.T) {
	if paths := BuildPaths(loadGraph(t, "hardened.yaml"), false); len(paths) != 0 {
		t.Errorf("hardened: %d paths, want 0", len(paths))
	}
}

// assume-breach surfaces a path for a non-exposed, non-privileged workload whose
// ServiceAccount holds dangerous RBAC; default mode does not.
func TestAssumeBreachSeedsReachability(t *testing.T) {
	g := &graph.Graph{
		Workloads: []model.Workload{{
			Resource:           model.Resource{Kind: "Deployment", Name: "ops", Namespace: "ns"},
			ServiceAccountName: "ops-sa",
			PodSpec:            model.PodSpecView{Containers: []model.ContainerView{{Name: "c", Image: "ops:1.0"}}},
		}},
		ClusterRoleBindings: []model.ClusterRoleBinding{{
			Resource: model.Resource{Kind: "ClusterRoleBinding", Name: "ops-admin"},
			RoleRef:  model.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []model.Subject{{Kind: "ServiceAccount", Name: "ops-sa", Namespace: "ns"}},
		}},
	}
	if def := BuildPaths(g, false); len(def) != 0 {
		t.Errorf("default mode: %d paths, want 0 (not reachable, not privileged)", len(def))
	}
	breach := BuildPaths(g, true)
	if len(breach) != 1 {
		t.Fatalf("assume-breach: %d paths, want 1", len(breach))
	}
	if !reaches(breach[0], api.CapClusterAdmin) {
		t.Error("assume-breach path should reach cluster-admin via the bound SA token")
	}
}

func TestSecretsAndPodCreateBranch(t *testing.T) {
	g := &graph.Graph{
		Workloads: []model.Workload{{
			Resource:           model.Resource{Kind: "Deployment", Name: "ops", Namespace: "ns"},
			ServiceAccountName: "ops-sa",
			PodSpec:            model.PodSpecView{Containers: []model.ContainerView{{Name: "c", Image: "ops:1.0"}}},
		}},
		Roles: []model.Role{{
			Resource: model.Resource{Kind: "Role", Name: "ops-role", Namespace: "ns"},
			Rules: []model.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
			},
		}},
		RoleBindings: []model.RoleBinding{{
			Resource: model.Resource{Kind: "RoleBinding", Name: "ops-rb", Namespace: "ns"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "ops-role"},
			Subjects: []model.Subject{{Kind: "ServiceAccount", Name: "ops-sa", Namespace: "ns"}},
		}},
	}
	paths := BuildPaths(g, true)
	if len(paths) != 1 {
		t.Fatalf("%d paths, want 1", len(paths))
	}
	p := paths[0]
	if !reaches(p, api.CapSecretRead) || !reaches(p, api.CapPodCreate) {
		t.Errorf("expected SecretRead and PodCreate hops, got chain %v", chainCaps(p))
	}
	if reaches(p, api.CapClusterAdmin) {
		t.Error("must not reach cluster-admin without an admin binding")
	}
	if p.Title != "Secret exfiltration via ops" {
		t.Errorf("title = %q", p.Title)
	}
}

func TestDangerousCapEscapeAndNodePort(t *testing.T) {
	g := &graph.Graph{
		Workloads: []model.Workload{{
			Resource:           model.Resource{Kind: "Deployment", Name: "app", Namespace: "ns"},
			ServiceAccountName: "app-sa",
			PodLabels:          map[string]string{"app": "app"},
			PodSpec: model.PodSpecView{
				Containers: []model.ContainerView{{Name: "c", Image: "app:1.0", CapsAdd: []string{"SYS_ADMIN"}}},
			},
		}},
		Services: []model.Service{{
			Resource: model.Resource{Kind: "Service", Name: "np", Namespace: "ns"},
			Type:     "NodePort", Selector: map[string]string{"app": "app"},
		}},
	}
	paths := BuildPaths(g, false)
	if len(paths) != 1 {
		t.Fatalf("%d paths, want 1", len(paths))
	}
	p := paths[0]
	if p.Hops[0].From != api.CapInternetIngress {
		t.Errorf("NodePort should seed InternetIngress, got %s", p.Hops[0].From)
	}
	if p.Hops[1].EnabledBy != "KG-008" {
		t.Errorf("escape enabler = %s, want KG-008 (SYS_ADMIN)", p.Hops[1].EnabledBy)
	}
	if !reaches(p, api.CapNodeAccess) {
		t.Error("dangerous-cap escape should reach node access")
	}
}

func TestDeterministicPaths(t *testing.T) {
	g := loadGraph(t, "vulnerable.yaml")
	first, _ := json.Marshal(BuildPaths(g, false))
	for i := 0; i < 5; i++ {
		if got, _ := json.Marshal(BuildPaths(g, false)); !bytes.Equal(first, got) {
			t.Fatal("non-deterministic path output")
		}
	}
}

// --- helpers --------------------------------------------------------------

func chainCaps(p api.AttackPath) []api.Capability {
	if len(p.Hops) == 0 {
		return nil
	}
	out := []api.Capability{p.Hops[0].From}
	for _, h := range p.Hops {
		out = append(out, h.To)
	}
	return out
}

func enablers(p api.AttackPath) []string {
	out := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		out[i] = h.EnabledBy
	}
	return out
}

func reaches(p api.AttackPath, c api.Capability) bool {
	for _, h := range p.Hops {
		if h.To == c {
			return true
		}
	}
	return false
}

func equalCaps(a, b []api.Capability) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func lf(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
