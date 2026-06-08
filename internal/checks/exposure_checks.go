package checks

import (
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

type exposureCheck struct{}

func (exposureCheck) Meta() Meta {
	return Meta{
		ID: "KG-018", Title: "Service exposed externally", Severity: api.SeverityMedium,
		Category: catExposure, Grants: []api.Capability{api.CapInternetIngress},
		Refs:        []api.ControlRef{nsa("Network separation"), attack("T1190")},
		Remediation: "Avoid direct LoadBalancer/NodePort exposure; front workloads with an ingress + WAF and restrict source ranges.",
	}
}

func (m exposureCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, svc := range g.Services {
		if svc.Type != "LoadBalancer" && svc.Type != "NodePort" {
			continue
		}
		f := m.Meta().finding(ref(svc.Resource), ev("spec.type", svc.Type))
		// Escalate when a LoadBalancer fronts a workload that is itself dangerous.
		if svc.Type == "LoadBalancer" && frontsDangerousWorkload(g, svc) {
			f.Severity = api.SeverityHigh
		}
		out = append(out, f)
	}
	return out
}

func frontsDangerousWorkload(g *graph.Graph, svc model.Service) bool {
	for _, w := range g.WorkloadsForService(svc) {
		if workloadDangerous(g, w) {
			return true
		}
	}
	return false
}

func workloadDangerous(g *graph.Graph, w model.Workload) bool {
	for _, c := range w.PodSpec.Containers {
		if c.Privileged {
			return true
		}
	}
	for _, v := range w.PodSpec.Volumes {
		if v.HostPath != "" {
			return true
		}
	}
	return g.SAIsClusterAdmin(w.Namespace, w.ServiceAccountName)
}
