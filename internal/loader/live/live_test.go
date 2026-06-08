package live

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/graph"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func bp(b bool) *bool { return &b }

func vulnerableObjects() []runtime.Object {
	labels := map[string]string{"app": "checkout"}
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "checkout-sa", Namespace: "payments"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments", Labels: labels},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec: corev1.PodSpec{
						ServiceAccountName: "checkout-sa",
						Containers: []corev1.Container{{
							Name:            "checkout",
							Image:           "checkout:latest",
							SecurityContext: &corev1.SecurityContext{Privileged: bp(true)},
						}},
					},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-cluster-admin"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "checkout-sa", Namespace: "payments"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-lb", Namespace: "payments"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: labels},
		},
	}
}

func TestLiveLoadFindsVulnerabilities(t *testing.T) {
	cs := fake.NewSimpleClientset(vulnerableObjects()...)

	resources, err := Load(context.Background(), cs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(resources) != 5 {
		t.Fatalf("loaded %d resources, want 5", len(resources))
	}

	g := graph.Build(resources)
	if len(g.Workloads) != 1 || g.Workloads[0].Name != "checkout" {
		t.Fatalf("workload not normalized from live: %+v", g.Workloads)
	}
	prof, _ := checks.ProfileByName("zeal-default")
	findings := checks.Scan(g, prof)

	want := map[string]bool{"KG-001": false, "KG-011": false, "KG-018": false}
	for _, f := range findings {
		if _, ok := want[f.ID]; ok {
			want[f.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("live scan missing expected finding %s", id)
		}
	}

	// The loader must be strictly read-only: every API action is a list.
	for _, a := range cs.Actions() {
		if a.GetVerb() != "list" {
			t.Errorf("non-read-only action: %s %s", a.GetVerb(), a.GetResource().Resource)
		}
	}
}

func TestLiveLoadEmptyCluster(t *testing.T) {
	cs := fake.NewSimpleClientset()
	resources, err := Load(context.Background(), cs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("empty cluster should yield 0 resources, got %d", len(resources))
	}
}

func TestLiveLoadSurfacesListError(t *testing.T) {
	resources := []string{
		"namespaces", "serviceaccounts", "pods", "services",
		"deployments", "statefulsets", "daemonsets",
		"jobs", "cronjobs",
		"roles", "clusterroles", "rolebindings", "clusterrolebindings",
		"networkpolicies",
	}
	for _, res := range resources {
		t.Run(res, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			cs.PrependReactor("list", res, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("api unreachable")
			})
			_, err := Load(context.Background(), cs)
			if err == nil || !strings.Contains(err.Error(), "list "+res) {
				t.Errorf("expected wrapped %q list error, got %v", res, err)
			}
		})
	}
}

func TestNewClientsetBadKubeconfig(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(empty, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", empty)
	if _, err := NewClientset(""); err == nil {
		t.Error("expected error from empty kubeconfig")
	}
}
