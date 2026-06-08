package graph

import (
	"encoding/json"
	"strconv"

	"github.com/kubeguard/kubeguard/internal/model"
)

// --- raw decode structs (Kubernetes-shaped, internal) ---------------------

type rawMeta struct {
	Labels map[string]string `json:"labels"`
}

type rawCaps struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type rawSeccomp struct {
	Type string `json:"type"`
}

type rawSecCtx struct {
	Privileged               *bool       `json:"privileged"`
	AllowPrivilegeEscalation *bool       `json:"allowPrivilegeEscalation"`
	RunAsUser                *int64      `json:"runAsUser"`
	RunAsNonRoot             *bool       `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem   *bool       `json:"readOnlyRootFilesystem"`
	Capabilities             *rawCaps    `json:"capabilities"`
	SeccompProfile           *rawSeccomp `json:"seccompProfile"`
}

type rawPodSecCtx struct {
	RunAsUser      *int64      `json:"runAsUser"`
	RunAsNonRoot   *bool       `json:"runAsNonRoot"`
	SeccompProfile *rawSeccomp `json:"seccompProfile"`
}

type rawResources struct {
	Limits struct {
		CPU    string `json:"cpu"`
		Memory string `json:"memory"`
	} `json:"limits"`
}

type rawEnvVar struct {
	Name      string `json:"name"`
	ValueFrom *struct {
		SecretKeyRef *struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		} `json:"secretKeyRef"`
	} `json:"valueFrom"`
}

type rawContainer struct {
	Name            string        `json:"name"`
	Image           string        `json:"image"`
	SecurityContext *rawSecCtx    `json:"securityContext"`
	Resources       *rawResources `json:"resources"`
	Env             []rawEnvVar   `json:"env"`
}

type rawVolume struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"hostPath"`
}

type rawPodSpec struct {
	ServiceAccountName           string         `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool          `json:"automountServiceAccountToken"`
	HostNetwork                  bool           `json:"hostNetwork"`
	HostPID                      bool           `json:"hostPID"`
	HostIPC                      bool           `json:"hostIPC"`
	SecurityContext              *rawPodSecCtx  `json:"securityContext"`
	Volumes                      []rawVolume    `json:"volumes"`
	Containers                   []rawContainer `json:"containers"`
	InitContainers               []rawContainer `json:"initContainers"`
	EphemeralContainers          []rawContainer `json:"ephemeralContainers"`
}

type rawTemplate struct {
	Metadata rawMeta    `json:"metadata"`
	Spec     rawPodSpec `json:"spec"`
}

// --- normalization --------------------------------------------------------

var workloadKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true,
	"DaemonSet": true, "Job": true, "CronJob": true,
}

func isWorkloadKind(kind string) bool { return workloadKinds[kind] }

// toWorkload normalizes a workload resource into a model.Workload. It returns
// false if the resource is not a workload kind or cannot be decoded.
func toWorkload(r model.Resource) (model.Workload, bool) {
	if !isWorkloadKind(r.Kind) {
		return model.Workload{}, false
	}
	b, err := json.Marshal(r.Raw)
	if err != nil {
		return model.Workload{}, false
	}

	var tmpl rawTemplate
	var podLabels map[string]string
	replicas := 1

	switch r.Kind {
	case "Pod":
		var m struct {
			Spec rawPodSpec `json:"spec"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return model.Workload{}, false
		}
		tmpl.Spec = m.Spec
		podLabels = r.Labels
	case "CronJob":
		var m struct {
			Spec struct {
				JobTemplate struct {
					Spec struct {
						Template rawTemplate `json:"template"`
					} `json:"spec"`
				} `json:"jobTemplate"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return model.Workload{}, false
		}
		tmpl = m.Spec.JobTemplate.Spec.Template
		podLabels = tmpl.Metadata.Labels
	default: // Deployment, StatefulSet, DaemonSet, Job
		var m struct {
			Spec struct {
				Replicas *int        `json:"replicas"`
				Template rawTemplate `json:"template"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return model.Workload{}, false
		}
		tmpl = m.Spec.Template
		podLabels = tmpl.Metadata.Labels
		if m.Spec.Replicas != nil {
			replicas = *m.Spec.Replicas
		}
	}

	saName := tmpl.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}

	return model.Workload{
		Resource:           r,
		Replicas:           replicas,
		ServiceAccountName: saName,
		PodLabels:          podLabels,
		PodSpec:            buildPodSpec(tmpl.Spec),
	}, true
}

func buildPodSpec(s rawPodSpec) model.PodSpecView {
	v := model.PodSpecView{
		HostNetwork:      s.HostNetwork,
		HostPID:          s.HostPID,
		HostIPC:          s.HostIPC,
		AutomountSAToken: s.AutomountServiceAccountToken,
	}
	if s.SecurityContext != nil {
		v.SecurityContext = model.SecurityContextView{
			RunAsUser:      s.SecurityContext.RunAsUser,
			RunAsNonRoot:   s.SecurityContext.RunAsNonRoot,
			SeccompProfile: seccompType(s.SecurityContext.SeccompProfile),
		}
	}
	for _, vol := range s.Volumes {
		vv := model.VolumeView{Name: vol.Name}
		if vol.HostPath != nil {
			vv.HostPath = vol.HostPath.Path
			vv.HostPathType = vol.HostPath.Type
		}
		v.Volumes = append(v.Volumes, vv)
	}
	v.Containers = append(v.Containers, buildContainers(s.InitContainers, "init")...)
	v.Containers = append(v.Containers, buildContainers(s.Containers, "container")...)
	v.Containers = append(v.Containers, buildContainers(s.EphemeralContainers, "ephemeral")...)
	return v
}

func buildContainers(cs []rawContainer, role string) []model.ContainerView {
	out := make([]model.ContainerView, 0, len(cs))
	for _, c := range cs {
		cv := model.ContainerView{
			Name:  c.Name,
			Image: c.Image,
			Role:  role,
		}
		if c.SecurityContext != nil {
			sc := c.SecurityContext
			cv.Privileged = sc.Privileged != nil && *sc.Privileged
			cv.AllowPrivEsc = sc.AllowPrivilegeEscalation
			cv.RunAsUser = sc.RunAsUser
			cv.RunAsNonRoot = sc.RunAsNonRoot
			cv.ReadOnlyRootFS = sc.ReadOnlyRootFilesystem
			if sc.Capabilities != nil {
				cv.CapsAdd = sc.Capabilities.Add
				cv.CapsDrop = sc.Capabilities.Drop
			}
			cv.SeccompProfile = seccompType(sc.SeccompProfile)
		}
		if c.Resources != nil {
			cv.Limits = model.ResourceLimitsView{
				CPU:    c.Resources.Limits.CPU,
				Memory: c.Resources.Limits.Memory,
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				cv.EnvSecretKeys = append(cv.EnvSecretKeys, e.Name)
			}
		}
		out = append(out, cv)
	}
	return out
}

func seccompType(p *rawSeccomp) string {
	if p == nil {
		return ""
	}
	return p.Type
}

// --- RBAC / service / network decode --------------------------------------

func toServiceAccount(r model.Resource) model.ServiceAccount {
	var m struct {
		Automount *bool `json:"automountServiceAccountToken"`
	}
	decodeInto(r.Raw, &m)
	return model.ServiceAccount{Resource: r, AutomountToken: m.Automount}
}

func toRules(r model.Resource) []model.PolicyRule {
	var m struct {
		Rules []struct {
			APIGroups     []string `json:"apiGroups"`
			Resources     []string `json:"resources"`
			Verbs         []string `json:"verbs"`
			ResourceNames []string `json:"resourceNames"`
		} `json:"rules"`
	}
	decodeInto(r.Raw, &m)
	out := make([]model.PolicyRule, 0, len(m.Rules))
	for _, rule := range m.Rules {
		out = append(out, model.PolicyRule{
			APIGroups:     rule.APIGroups,
			Resources:     rule.Resources,
			Verbs:         rule.Verbs,
			ResourceNames: rule.ResourceNames,
		})
	}
	return out
}

func toBinding(r model.Resource) (model.RoleRef, []model.Subject) {
	var m struct {
		RoleRef struct {
			Kind     string `json:"kind"`
			Name     string `json:"name"`
			APIGroup string `json:"apiGroup"`
		} `json:"roleRef"`
		Subjects []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"subjects"`
	}
	decodeInto(r.Raw, &m)
	ref := model.RoleRef{Kind: m.RoleRef.Kind, Name: m.RoleRef.Name, APIGroup: m.RoleRef.APIGroup}
	subs := make([]model.Subject, 0, len(m.Subjects))
	for _, s := range m.Subjects {
		subs = append(subs, model.Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
	}
	return ref, subs
}

func toService(r model.Resource) model.Service {
	var m struct {
		Spec struct {
			Type     string            `json:"type"`
			Selector map[string]string `json:"selector"`
			Ports    []struct {
				Port       int    `json:"port"`
				TargetPort any    `json:"targetPort"`
				Protocol   string `json:"protocol"`
				NodePort   int    `json:"nodePort"`
			} `json:"ports"`
		} `json:"spec"`
	}
	decodeInto(r.Raw, &m)
	svc := model.Service{Resource: r, Type: m.Spec.Type, Selector: m.Spec.Selector}
	if svc.Type == "" {
		svc.Type = "ClusterIP"
	}
	for _, p := range m.Spec.Ports {
		svc.Ports = append(svc.Ports, model.ServicePort{
			Port:       p.Port,
			TargetPort: stringifyPort(p.TargetPort),
			Protocol:   p.Protocol,
			NodePort:   p.NodePort,
		})
	}
	return svc
}

func toNetworkPolicy(r model.Resource) model.NetworkPolicy {
	var m struct {
		Spec struct {
			PodSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"podSelector"`
			PolicyTypes []string `json:"policyTypes"`
			Ingress     []any    `json:"ingress"`
			Egress      []any    `json:"egress"`
		} `json:"spec"`
	}
	decodeInto(r.Raw, &m)
	return model.NetworkPolicy{
		Resource:         r,
		PodSelector:      m.Spec.PodSelector.MatchLabels,
		PolicyTypes:      m.Spec.PolicyTypes,
		IngressRuleCount: len(m.Spec.Ingress),
		EgressRuleCount:  len(m.Spec.Egress),
	}
}

// decodeInto round-trips a raw map through JSON into a typed target. Errors are
// ignored deliberately: a malformed sub-tree yields zero values for those
// fields rather than failing the whole load.
func decodeInto(raw map[string]any, target any) {
	b, err := json.Marshal(raw)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, target)
}

func stringifyPort(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if i := int64(t); float64(i) == t {
			return strconv.FormatInt(i, 10)
		}
	}
	return ""
}
