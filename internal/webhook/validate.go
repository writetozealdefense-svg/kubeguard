package webhook

import (
	"encoding/json"
	"fmt"

	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
	corev1 "k8s.io/api/core/v1"
)

// denyChecks are the checks that constitute an admission violation under a
// restricted profile: host access and run-as-root (ARCHITECTURE.md §14).
var denyChecks = map[string]bool{
	"KG-001": true, // privileged container
	"KG-002": true, // sensitive hostPath mount
	"KG-003": true, // hostNetwork
	"KG-004": true, // hostPID
	"KG-005": true, // hostIPC
	"KG-006": true, // runs as root
	"KG-008": true, // dangerous capabilities
}

// Violations runs the pod-level checks against a single Pod and returns the
// deny-worthy findings. It reuses the detection engine so the webhook and the
// scanner never diverge.
func Violations(pod *corev1.Pod) ([]api.Finding, error) {
	res, err := podResource(pod)
	if err != nil {
		return nil, err
	}
	g := graph.Build([]model.Resource{res})
	profile, _ := checks.ProfileByName("zeal-default")

	var out []api.Finding
	for _, f := range checks.Scan(g, profile) {
		if denyChecks[f.ID] {
			out = append(out, f)
		}
	}
	return out, nil
}

func podResource(pod *corev1.Pod) (model.Resource, error) {
	b, err := json.Marshal(pod)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal pod: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return model.Resource{}, fmt.Errorf("decode pod: %w", err)
	}
	raw["kind"] = "Pod"
	raw["apiVersion"] = "v1"

	name := pod.Name
	if name == "" {
		name = pod.GenerateName + "(generated)"
	}
	return model.Resource{
		Kind:       "Pod",
		APIVersion: "v1",
		Namespace:  pod.Namespace,
		Name:       name,
		Labels:     pod.Labels,
		UID:        string(pod.UID),
		Raw:        raw,
	}, nil
}
