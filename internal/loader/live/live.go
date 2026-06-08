package live

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubeguard/kubeguard/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ptrObject constrains *T to satisfy metav1.Object (every k8s list item does).
type ptrObject[T any] interface {
	*T
	metav1.Object
}

// Load ingests cluster resources read-only via a client-go clientset and
// converts them to the same model.Resource set the offline loader produces
// (ARCHITECTURE.md §5.2). It only ever lists; it never writes.
func Load(ctx context.Context, cs kubernetes.Interface) ([]model.Resource, error) {
	all := metav1.NamespaceAll
	o := metav1.ListOptions{}
	var out []model.Resource

	steps := []func() error{
		func() error {
			l, err := cs.CoreV1().Namespaces().List(ctx, o)
			if err != nil {
				return wrap("namespaces", err)
			}
			return addAll[corev1.Namespace, *corev1.Namespace](&out, "Namespace", "v1", l.Items)
		},
		func() error {
			l, err := cs.CoreV1().ServiceAccounts(all).List(ctx, o)
			if err != nil {
				return wrap("serviceaccounts", err)
			}
			return addAll[corev1.ServiceAccount, *corev1.ServiceAccount](&out, "ServiceAccount", "v1", l.Items)
		},
		func() error {
			l, err := cs.CoreV1().Pods(all).List(ctx, o)
			if err != nil {
				return wrap("pods", err)
			}
			return addAll[corev1.Pod, *corev1.Pod](&out, "Pod", "v1", l.Items)
		},
		func() error {
			l, err := cs.CoreV1().Services(all).List(ctx, o)
			if err != nil {
				return wrap("services", err)
			}
			return addAll[corev1.Service, *corev1.Service](&out, "Service", "v1", l.Items)
		},
		func() error {
			l, err := cs.AppsV1().Deployments(all).List(ctx, o)
			if err != nil {
				return wrap("deployments", err)
			}
			return addAll[appsv1.Deployment, *appsv1.Deployment](&out, "Deployment", "apps/v1", l.Items)
		},
		func() error {
			l, err := cs.AppsV1().StatefulSets(all).List(ctx, o)
			if err != nil {
				return wrap("statefulsets", err)
			}
			return addAll[appsv1.StatefulSet, *appsv1.StatefulSet](&out, "StatefulSet", "apps/v1", l.Items)
		},
		func() error {
			l, err := cs.AppsV1().DaemonSets(all).List(ctx, o)
			if err != nil {
				return wrap("daemonsets", err)
			}
			return addAll[appsv1.DaemonSet, *appsv1.DaemonSet](&out, "DaemonSet", "apps/v1", l.Items)
		},
		func() error {
			l, err := cs.BatchV1().Jobs(all).List(ctx, o)
			if err != nil {
				return wrap("jobs", err)
			}
			return addAll[batchv1.Job, *batchv1.Job](&out, "Job", "batch/v1", l.Items)
		},
		func() error {
			l, err := cs.BatchV1().CronJobs(all).List(ctx, o)
			if err != nil {
				return wrap("cronjobs", err)
			}
			return addAll[batchv1.CronJob, *batchv1.CronJob](&out, "CronJob", "batch/v1", l.Items)
		},
		func() error {
			l, err := cs.RbacV1().Roles(all).List(ctx, o)
			if err != nil {
				return wrap("roles", err)
			}
			return addAll[rbacv1.Role, *rbacv1.Role](&out, "Role", "rbac.authorization.k8s.io/v1", l.Items)
		},
		func() error {
			l, err := cs.RbacV1().ClusterRoles().List(ctx, o)
			if err != nil {
				return wrap("clusterroles", err)
			}
			return addAll[rbacv1.ClusterRole, *rbacv1.ClusterRole](&out, "ClusterRole", "rbac.authorization.k8s.io/v1", l.Items)
		},
		func() error {
			l, err := cs.RbacV1().RoleBindings(all).List(ctx, o)
			if err != nil {
				return wrap("rolebindings", err)
			}
			return addAll[rbacv1.RoleBinding, *rbacv1.RoleBinding](&out, "RoleBinding", "rbac.authorization.k8s.io/v1", l.Items)
		},
		func() error {
			l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, o)
			if err != nil {
				return wrap("clusterrolebindings", err)
			}
			return addAll[rbacv1.ClusterRoleBinding, *rbacv1.ClusterRoleBinding](&out, "ClusterRoleBinding", "rbac.authorization.k8s.io/v1", l.Items)
		},
		func() error {
			l, err := cs.NetworkingV1().NetworkPolicies(all).List(ctx, o)
			if err != nil {
				return wrap("networkpolicies", err)
			}
			return addAll[networkingv1.NetworkPolicy, *networkingv1.NetworkPolicy](&out, "NetworkPolicy", "networking.k8s.io/v1", l.Items)
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func wrap(kind string, err error) error { return fmt.Errorf("list %s: %w", kind, err) }

func addAll[T any, P ptrObject[T]](out *[]model.Resource, kind, apiVersion string, list []T) error {
	for i := range list {
		if err := add[T, P](out, kind, apiVersion, &list[i]); err != nil {
			return err
		}
	}
	return nil
}

func add[T any, P ptrObject[T]](out *[]model.Resource, kind, apiVersion string, obj P) error {
	raw, err := toRaw(obj)
	if err != nil {
		return fmt.Errorf("encode %s/%s: %w", kind, obj.GetName(), err)
	}
	raw["kind"] = kind
	raw["apiVersion"] = apiVersion

	r := model.Resource{
		Kind:        kind,
		APIVersion:  apiVersion,
		Namespace:   obj.GetNamespace(),
		Name:        obj.GetName(),
		Labels:      obj.GetLabels(),
		Annotations: obj.GetAnnotations(),
		UID:         string(obj.GetUID()),
		Raw:         raw,
	}
	if r.UID == "" {
		r.UID = r.Ref()
	}
	*out = append(*out, r)
	return nil
}

func toRaw(obj any) (map[string]any, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
