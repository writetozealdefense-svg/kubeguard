package model

import "fmt"

// Resource is the minimal envelope for any loaded Kubernetes object. Raw holds
// the JSON-compatible decoded document, used for typed extraction and evidence.
type Resource struct {
	APIVersion  string
	Kind        string
	Namespace   string // "" for cluster-scoped
	Name        string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Raw         map[string]any
}

// Ref returns a stable human reference, e.g. "payments/Deployment/checkout".
func (r Resource) Ref() string {
	ns := r.Namespace
	if ns == "" {
		ns = "_cluster_"
	}
	return fmt.Sprintf("%s/%s/%s", ns, r.Kind, r.Name)
}

// Workload is the normalized view across Pod/Deployment/StatefulSet/DaemonSet/
// Job/CronJob (ARCHITECTURE.md §4.1, §6).
type Workload struct {
	Resource
	Replicas           int
	ServiceAccountName string // resolved; "default" if unset
	PodLabels          map[string]string
	PodSpec            PodSpecView
}

// PodSpecView flattens the security-relevant surface of a pod template.
type PodSpecView struct {
	HostNetwork      bool
	HostPID          bool
	HostIPC          bool
	AutomountSAToken *bool // nil = cluster default (true)
	Volumes          []VolumeView
	Containers       []ContainerView // init + regular + ephemeral, role-tagged
	SecurityContext  SecurityContextView
}

// VolumeView captures the subset of a volume KubeGuard reasons over.
type VolumeView struct {
	Name         string
	HostPath     string // "" if this is not a hostPath volume
	HostPathType string
}

// ContainerView is the normalized security view of a single container.
type ContainerView struct {
	Name           string
	Image          string
	Role           string // "init" | "container" | "ephemeral"
	Privileged     bool
	AllowPrivEsc   *bool
	RunAsUser      *int64
	RunAsNonRoot   *bool
	ReadOnlyRootFS *bool
	CapsAdd        []string
	CapsDrop       []string
	SeccompProfile string   // "", "RuntimeDefault", "Unconfined", "Localhost"
	EnvSecretKeys  []string // env var names sourced from secrets; values never captured
	Limits         ResourceLimitsView
}

// SecurityContextView is the pod-level security context subset.
type SecurityContextView struct {
	RunAsUser      *int64
	RunAsNonRoot   *bool
	SeccompProfile string
}

// ResourceLimitsView captures CPU/memory limits ("" when unset).
type ResourceLimitsView struct {
	CPU    string
	Memory string
}

// HasLimits reports whether both CPU and memory limits are set.
func (l ResourceLimitsView) HasLimits() bool {
	return l.CPU != "" && l.Memory != ""
}

// ServiceAccount is the normalized SA view.
type ServiceAccount struct {
	Resource
	AutomountToken *bool
}

// PolicyRule is a single RBAC rule.
type PolicyRule struct {
	APIGroups     []string
	Resources     []string
	Verbs         []string
	ResourceNames []string
}

// Role is a namespaced RBAC role.
type Role struct {
	Resource
	Rules []PolicyRule
}

// ClusterRole is a cluster-scoped RBAC role.
type ClusterRole struct {
	Resource
	Rules []PolicyRule
}

// RoleRef identifies the role a binding grants.
type RoleRef struct {
	Kind     string // "Role" | "ClusterRole"
	Name     string
	APIGroup string
}

// Subject is a binding subject.
type Subject struct {
	Kind      string // "ServiceAccount" | "User" | "Group"
	Name      string
	Namespace string
}

// RoleBinding binds a Role/ClusterRole to subjects within a namespace.
type RoleBinding struct {
	Resource
	RoleRef  RoleRef
	Subjects []Subject
}

// ClusterRoleBinding binds a ClusterRole to subjects cluster-wide.
type ClusterRoleBinding struct {
	Resource
	RoleRef  RoleRef
	Subjects []Subject
}

// Service is the normalized service view.
type Service struct {
	Resource
	Type     string // ClusterIP | NodePort | LoadBalancer | ExternalName
	Selector map[string]string
	Ports    []ServicePort
}

// ServicePort captures a single service port.
type ServicePort struct {
	Port       int
	TargetPort string
	Protocol   string
	NodePort   int
}

// NetworkPolicy is the normalized network policy view. RuleCounts and the
// empty-selector signal let checks detect a namespace default-deny.
type NetworkPolicy struct {
	Resource
	PodSelector      map[string]string
	PolicyTypes      []string
	IngressRuleCount int
	EgressRuleCount  int
}

// IsDefaultDeny reports whether this policy denies all traffic of its declared
// policy types to all pods in the namespace (empty selector, no allow rules).
func (n NetworkPolicy) IsDefaultDeny() bool {
	if len(n.PodSelector) != 0 {
		return false
	}
	denies := false
	for _, t := range n.PolicyTypes {
		if t == "Ingress" && n.IngressRuleCount == 0 {
			denies = true
		}
		if t == "Egress" && n.EgressRuleCount == 0 {
			denies = true
		}
	}
	return denies
}
