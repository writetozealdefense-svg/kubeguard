package graph

import (
	"sort"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// assessedKinds are the resource kinds the graph normalizes and the built-in
// checks reason over. A discovered resource of any other kind is counted as
// skipped (with the reason that no built-in check evaluates it) rather than
// silently dropped — the same honesty rule as compliance denominators.
var assessedKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true,
	"ServiceAccount": true, "Role": true, "ClusterRole": true,
	"RoleBinding": true, "ClusterRoleBinding": true,
	"Service": true, "NetworkPolicy": true, "Namespace": true,
}

// Coverage reports the assessment-coverage breakdown over the discovered
// inventory: how many resources were discovered, how many are assessable, and
// how many were skipped (tallied by kind). Deterministic — the skipped-by-kind
// map is built from a stable pass over Resources. Rate is assessable/discovered
// (0 when nothing was discovered).
func (g *Graph) Coverage() api.CoverageBreakdown {
	cov := api.CoverageBreakdown{Discovered: len(g.Resources)}
	skipped := map[string]int{}
	for _, r := range g.Resources {
		if assessedKinds[r.Kind] {
			cov.Assessable++
			continue
		}
		kind := r.Kind
		if kind == "" {
			kind = "(unknown)"
		}
		skipped[kind]++
	}
	cov.Skipped = cov.Discovered - cov.Assessable
	if cov.Discovered > 0 {
		cov.Rate = float64(cov.Assessable) / float64(cov.Discovered)
	}
	if len(skipped) > 0 {
		// Copy into a fresh map; the keys are already deterministic (sorted here
		// only to keep any future ordered rendering stable).
		cov.SkippedByKind = make(map[string]int, len(skipped))
		kinds := make([]string, 0, len(skipped))
		for k := range skipped {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			cov.SkippedByKind[k] = skipped[k]
		}
	}
	return cov
}
