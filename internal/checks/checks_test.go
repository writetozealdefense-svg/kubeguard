package checks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

const fixturesDir = "../../test/fixtures"

// --- builders -------------------------------------------------------------

func tru() *bool         { b := true; return &b }
func fls() *bool         { b := false; return &b }
func i64(v int64) *int64 { return &v }

// cleanWorkload is a fully hardened workload that triggers zero checks.
func cleanWorkload() model.Workload {
	return model.Workload{
		Resource:           model.Resource{Kind: "Deployment", Name: "app", Namespace: "ns"},
		ServiceAccountName: "app-sa",
		PodLabels:          map[string]string{"app": "app"},
		PodSpec: model.PodSpecView{
			AutomountSAToken: fls(),
			Containers: []model.ContainerView{{
				Name:           "c",
				Image:          "reg.example.com/app:1.0@sha256:" + strings.Repeat("a", 64),
				AllowPrivEsc:   fls(),
				RunAsNonRoot:   tru(),
				RunAsUser:      i64(1000),
				ReadOnlyRootFS: tru(),
				CapsDrop:       []string{"ALL"},
				SeccompProfile: "RuntimeDefault",
				Limits:         model.ResourceLimitsView{CPU: "100m", Memory: "128Mi"},
			}},
		},
	}
}

func gw(ws ...model.Workload) *graph.Graph { return &graph.Graph{Workloads: ws} }

func mutate(fn func(*model.Workload)) *graph.Graph {
	w := cleanWorkload()
	fn(&w)
	return gw(w)
}

func saSubject() []model.Subject {
	return []model.Subject{{Kind: "ServiceAccount", Name: "app-sa", Namespace: "ns"}}
}

func runCheck(t *testing.T, id string, g *graph.Graph) []api.Finding {
	t.Helper()
	for _, c := range Registry() {
		if c.Meta().ID == id {
			return c.Run(g)
		}
	}
	t.Fatalf("no check with id %s", id)
	return nil
}

// --- positive / negative per check ---------------------------------------

func TestEachCheckPositiveAndNegative(t *testing.T) {
	readerRole := model.Role{
		Resource: model.Resource{Kind: "Role", Name: "reader", Namespace: "ns"},
		Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
	}
	cleanRBACGraph := &graph.Graph{
		Roles: []model.Role{readerRole},
		RoleBindings: []model.RoleBinding{{
			Resource: model.Resource{Kind: "RoleBinding", Name: "rb", Namespace: "ns"},
			RoleRef:  model.RoleRef{Kind: "Role", Name: "reader"},
			Subjects: saSubject(),
		}},
	}

	cases := []struct {
		id  string
		pos *graph.Graph
		neg *graph.Graph
	}{
		{"KG-001", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].Privileged = true }), gw(cleanWorkload())},
		{"KG-002", mutate(func(w *model.Workload) {
			w.PodSpec.Volumes = []model.VolumeView{{Name: "sock", HostPath: "/var/run/docker.sock"}}
		}), gw(cleanWorkload())},
		{"KG-003", mutate(func(w *model.Workload) { w.PodSpec.HostNetwork = true }), gw(cleanWorkload())},
		{"KG-004", mutate(func(w *model.Workload) { w.PodSpec.HostPID = true }), gw(cleanWorkload())},
		{"KG-005", mutate(func(w *model.Workload) { w.PodSpec.HostIPC = true }), gw(cleanWorkload())},
		{"KG-006", mutate(func(w *model.Workload) {
			w.PodSpec.Containers[0].RunAsNonRoot = nil
			w.PodSpec.Containers[0].RunAsUser = i64(0)
		}), gw(cleanWorkload())},
		{"KG-007", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].AllowPrivEsc = nil }), gw(cleanWorkload())},
		{"KG-008", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].CapsAdd = []string{"SYS_ADMIN"} }), gw(cleanWorkload())},
		{"KG-009", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].ReadOnlyRootFS = nil }), gw(cleanWorkload())},
		{"KG-010", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].Limits = model.ResourceLimitsView{} }), gw(cleanWorkload())},
		{"KG-015", mutate(func(w *model.Workload) { w.PodSpec.AutomountSAToken = nil }), gw(cleanWorkload())},
		{"KG-016", mutate(func(w *model.Workload) { w.ServiceAccountName = "default" }), gw(cleanWorkload())},
		{"KG-019", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].Image = "app:latest" }), gw(cleanWorkload())},
		{"KG-020", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].SeccompProfile = "" }), gw(cleanWorkload())},
		{"KG-021", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].CapsDrop = nil }), gw(cleanWorkload())},
		{"KG-022", mutate(func(w *model.Workload) { w.PodSpec.Containers[0].Image = "app:latest" }), gw(cleanWorkload())},
		{
			"KG-011",
			&graph.Graph{ClusterRoleBindings: []model.ClusterRoleBinding{{
				Resource: model.Resource{Kind: "ClusterRoleBinding", Name: "crb"},
				RoleRef:  model.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: saSubject(),
			}}},
			cleanRBACGraph,
		},
		{
			"KG-012",
			&graph.Graph{ClusterRoles: []model.ClusterRole{{
				Resource: model.Resource{Kind: "ClusterRole", Name: "wild"},
				Rules:    []model.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			}}},
			cleanRBACGraph,
		},
		{
			"KG-013",
			&graph.Graph{Roles: []model.Role{{
				Resource: model.Resource{Kind: "Role", Name: "sec", Namespace: "ns"},
				Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}},
			}}},
			cleanRBACGraph,
		},
		{
			"KG-014",
			&graph.Graph{Roles: []model.Role{{
				Resource: model.Resource{Kind: "Role", Name: "podmaker", Namespace: "ns"},
				Rules:    []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}},
			}}},
			cleanRBACGraph,
		},
		{
			"KG-017",
			gw(cleanWorkload()),
			&graph.Graph{
				Workloads: []model.Workload{cleanWorkload()},
				NetworkPolicies: []model.NetworkPolicy{{
					Resource:    model.Resource{Kind: "NetworkPolicy", Name: "deny", Namespace: "ns"},
					PolicyTypes: []string{"Ingress", "Egress"},
				}},
			},
		},
		{
			"KG-018",
			&graph.Graph{Services: []model.Service{{
				Resource: model.Resource{Kind: "Service", Name: "lb", Namespace: "ns"},
				Type:     "LoadBalancer", Selector: map[string]string{"app": "app"},
			}}},
			&graph.Graph{Services: []model.Service{{
				Resource: model.Resource{Kind: "Service", Name: "cip", Namespace: "ns"},
				Type:     "ClusterIP", Selector: map[string]string{"app": "app"},
			}}},
		},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.id] = true
		t.Run(tc.id+"/positive", func(t *testing.T) {
			fs := runCheck(t, tc.id, tc.pos)
			if len(fs) == 0 {
				t.Fatalf("%s: expected a finding, got none", tc.id)
			}
			for _, f := range fs {
				if f.ID != tc.id {
					t.Errorf("%s: got finding with id %s", tc.id, f.ID)
				}
			}
		})
		t.Run(tc.id+"/negative", func(t *testing.T) {
			if fs := runCheck(t, tc.id, tc.neg); len(fs) != 0 {
				t.Errorf("%s: expected no findings, got %d", tc.id, len(fs))
			}
		})
	}

	for _, c := range Registry() {
		if !seen[c.Meta().ID] {
			t.Errorf("check %s has no positive/negative case", c.Meta().ID)
		}
	}
}

// --- registry & metadata --------------------------------------------------

func TestRegistryHas22UniqueChecks(t *testing.T) {
	reg := Registry()
	if len(reg) != 22 {
		t.Fatalf("registry has %d checks, want 22", len(reg))
	}
	ids := map[string]bool{}
	for _, c := range reg {
		m := c.Meta()
		if ids[m.ID] {
			t.Errorf("duplicate check id %s", m.ID)
		}
		ids[m.ID] = true
		if m.Title == "" || m.Category == "" || m.Severity == "" || m.Remediation == "" {
			t.Errorf("%s: incomplete metadata: %+v", m.ID, m)
		}
	}
}

// --- profile difference ---------------------------------------------------

func TestProfilesDifferOnExposure(t *testing.T) {
	g := loadGraph(t, "vulnerable.yaml")
	zeal := findByID(Scan(g, zealDefault()), "KG-018")
	cis := findByID(Scan(g, cisProfile()), "KG-018")
	if zeal == nil || cis == nil {
		t.Fatal("KG-018 missing in a profile")
	}
	if zeal.Severity != api.SeverityHigh {
		t.Errorf("zeal-default KG-018 = %s, want high", zeal.Severity)
	}
	if cis.Severity != api.SeverityMedium {
		t.Errorf("cis KG-018 = %s, want medium", cis.Severity)
	}
}

// --- golden + fixture-level expectations ----------------------------------

func TestVulnerableGolden(t *testing.T) {
	g := loadGraph(t, "vulnerable.yaml")
	findings := Scan(g, zealDefault())

	got, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join(fixturesDir, "golden", "vulnerable.findings.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(lf(got), lf(want)) {
		t.Errorf("findings differ from golden %s\n--- got ---\n%s", goldenPath, got)
	}
}

func TestFixtureFindingCounts(t *testing.T) {
	vuln := Scan(loadGraph(t, "vulnerable.yaml"), zealDefault())
	if !hasCritical(vuln) {
		t.Error("vulnerable must have >=1 critical finding")
	}
	for _, id := range []string{"KG-001", "KG-002", "KG-011", "KG-013", "KG-014", "KG-015", "KG-017", "KG-018"} {
		if findByID(vuln, id) == nil {
			t.Errorf("vulnerable missing expected finding %s", id)
		}
	}

	if hardened := Scan(loadGraph(t, "hardened.yaml"), zealDefault()); len(hardened) != 0 {
		t.Errorf("hardened must yield 0 findings, got %d: %v", len(hardened), ids(hardened))
	}

	if partial := Scan(loadGraph(t, "partially-hardened.yaml"), zealDefault()); findByID(partial, "KG-011") != nil {
		t.Error("partially-hardened must not have a cluster-admin (KG-011) finding")
	}
}

func TestDeterministicOrder(t *testing.T) {
	g := loadGraph(t, "vulnerable.yaml")
	first := ids(Scan(g, zealDefault()))
	for i := 0; i < 5; i++ {
		if got := ids(Scan(g, zealDefault())); !equalSlice(first, got) {
			t.Fatalf("non-deterministic order:\n%v\n%v", first, got)
		}
	}
	// Verify severity is non-increasing.
	fs := Scan(g, zealDefault())
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Severity.Rank() < fs[i].Severity.Rank() {
			t.Errorf("severity order violated at %d: %s before %s", i, fs[i-1].Severity, fs[i].Severity)
		}
	}
}

// --- helpers --------------------------------------------------------------

func loadGraph(t *testing.T, file string) *graph.Graph {
	t.Helper()
	rs, err := offline.Load(filepath.Join(fixturesDir, file))
	if err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
	return graph.Build(rs)
}

func findByID(fs []api.Finding, id string) *api.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func hasCritical(fs []api.Finding) bool {
	for _, f := range fs {
		if f.Severity == api.SeverityCritical {
			return true
		}
	}
	return false
}

func ids(fs []api.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func equalSlice(a, b []string) bool {
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
