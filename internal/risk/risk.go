// Package risk computes a deterministic, explainable priority score over the
// findings in a report, using only signals the engine already produces:
// severity, whether a finding enables an attack-path hop, whether that path is
// internet-reachable, the blast radius the path reaches (SA-token → node →
// cluster-admin), and how many workloads a check affects.
//
// The score is a plain weighted sum. Every contributing weight is recorded as a
// RiskFactor on the result, so the "why" is always attached and the score is
// fully reproducible run-to-run — no ML, no hidden terms (ARCHITECTURE.md §3
// honest-metrics rule). The weights are documented in docs/honest-metrics.md.
package risk

import (
	"sort"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// Weights — published in docs/honest-metrics.md. Kept here as the single source
// of truth so the docs and the code cannot silently diverge.
const (
	sevCritical = 50
	sevHigh     = 30
	sevMedium   = 15
	sevLow      = 5
	sevInfo     = 0

	pointsAttackEnabler = 25 // finding enables a hop in at least one attack path
	pointsInternet      = 20 // that path is reachable from the public internet
	pointsClusterAdmin  = 30 // that path reaches ClusterAdmin (max blast radius)
	pointsNodeAccess    = 20 // reaches NodeAccess
	pointsSAToken       = 10 // reaches ServiceAccountToken / SecretRead

	pointsPerExtraWorkload = 2 // per additional workload the same check affects
	maxBreadthBonus        = 10
)

func severityPoints(s api.Severity) int {
	switch s {
	case api.SeverityCritical:
		return sevCritical
	case api.SeverityHigh:
		return sevHigh
	case api.SeverityMedium:
		return sevMedium
	case api.SeverityLow:
		return sevLow
	default:
		return sevInfo
	}
}

// pathSignals summarizes, per finding-id that enables a hop, the strongest
// blast-radius reached across the paths it participates in and whether any such
// path is internet-reachable.
type pathSignals struct {
	internet    bool
	reachAdmin  bool
	reachNode   bool
	reachSAlike bool
}

// Score ranks a report's findings by risk, highest first. Deterministic: ties
// break by severity rank then finding id, so the order is stable run-to-run.
func Score(rep api.Report) []api.RiskScore {
	byFinding := analyzePaths(rep.Paths)

	// How many distinct resources each check id fired on (breadth signal).
	affected := map[string]map[string]struct{}{}
	for _, f := range rep.Findings {
		if affected[f.ID] == nil {
			affected[f.ID] = map[string]struct{}{}
		}
		affected[f.ID][resourceKey(f.Resource)] = struct{}{}
	}

	out := make([]api.RiskScore, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		rs := api.RiskScore{
			FindingID: f.ID, Title: f.Title, Severity: f.Severity, Resource: f.Resource,
		}
		add := func(name string, pts int, detail string) {
			if pts == 0 {
				return
			}
			rs.Score += pts
			rs.Factors = append(rs.Factors, api.RiskFactor{Name: name, Points: pts, Detail: detail})
		}

		add("severity", severityPoints(f.Severity), "base weight for "+string(f.Severity)+" severity")

		if sig, ok := byFinding[f.ID]; ok {
			add("attack-path-enabler", pointsAttackEnabler, "enables a step in at least one attack path")
			if sig.internet {
				add("internet-exposed", pointsInternet, "the enabled path is reachable from the public internet")
			}
			// Blast radius: award only the strongest reached outcome, not a sum,
			// so a chain to cluster-admin isn't triple-counted.
			switch {
			case sig.reachAdmin:
				add("blast-radius", pointsClusterAdmin, "the enabled path reaches cluster-admin")
			case sig.reachNode:
				add("blast-radius", pointsNodeAccess, "the enabled path reaches node access")
			case sig.reachSAlike:
				add("blast-radius", pointsSAToken, "the enabled path reaches a service-account token / secret read")
			}
		}

		if n := len(affected[f.ID]); n > 1 {
			bonus := (n - 1) * pointsPerExtraWorkload
			if bonus > maxBreadthBonus {
				bonus = maxBreadthBonus
			}
			add("breadth", bonus, "the check affects multiple workloads")
		}

		out = append(out, rs)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out
}

// analyzePaths derives, for every finding id that enables a hop, the blast
// radius and internet-reachability of the paths it appears in.
func analyzePaths(paths []api.AttackPath) map[string]pathSignals {
	byFinding := map[string]pathSignals{}
	for _, p := range paths {
		internet := false
		var reachAdmin, reachNode, reachSAlike bool
		for _, h := range p.Hops {
			if h.From == api.CapInternetIngress || h.To == api.CapInternetIngress {
				internet = true
			}
			switch h.To {
			case api.CapClusterAdmin:
				reachAdmin = true
			case api.CapNodeAccess:
				reachNode = true
			case api.CapServiceAccountToken, api.CapSecretRead:
				reachSAlike = true
			}
		}
		for _, h := range p.Hops {
			if h.EnabledBy == "" {
				continue
			}
			s := byFinding[h.EnabledBy]
			s.internet = s.internet || internet
			s.reachAdmin = s.reachAdmin || reachAdmin
			s.reachNode = s.reachNode || reachNode
			s.reachSAlike = s.reachSAlike || reachSAlike
			byFinding[h.EnabledBy] = s
		}
	}
	return byFinding
}

func resourceKey(r api.ResourceRef) string {
	return r.Kind + "/" + r.Namespace + "/" + r.Name
}
