// Package analyzer runs the full detect→chain→comply pipeline over a set of
// resources and assembles an api.Report. It is shared by the CLI scan command
// and the service mode so both produce identical results.
package analyzer

import (
	"github.com/kubeguard/kubeguard/internal/attack"
	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/compliance"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/internal/risk"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// ExtraChecks produces additional findings from the built graph — the seam for
// runtime custom policies (K3). It must be read-only over the graph.
type ExtraChecks func(g *graph.Graph) []api.Finding

// Analyze builds the graph, runs the checks, chains attack paths, and evaluates
// compliance. The caller sets Report.GeneratedAt and Report.Source. Optional
// extra finding-producers (e.g. custom CEL policies) are merged into the
// findings before posture/coverage/risk are computed, so their findings flow
// through the same report, posture, and gate surfaces as the built-ins.
func Analyze(resources []model.Resource, profileName string, assumeBreach bool, extra ...ExtraChecks) (api.Report, error) {
	profile, err := checks.ProfileByName(profileName)
	if err != nil {
		return api.Report{}, err
	}
	packs, err := compliance.LoadEmbedded()
	if err != nil {
		return api.Report{}, err
	}

	g := graph.Build(resources)
	findings := checks.Scan(g, profile)
	for _, ec := range extra {
		if ec == nil {
			continue
		}
		findings = append(findings, ec(g)...)
	}
	checks.SortFindings(findings) // keep deterministic order after merging custom findings
	paths := attack.BuildPaths(g, assumeBreach)
	frameworks := compliance.EvaluateAll(packs, profile.RunnableIDs(), compliance.FiredChecks(findings))

	coverage := g.Coverage()
	rep := api.Report{
		Profile:    profile.Name,
		Findings:   findings,
		Paths:      paths,
		Posture:    compliance.Summarize(findings, paths, frameworks),
		Compliance: frameworks,
		Coverage:   &coverage,
	}
	rep.TopRisks = risk.Score(rep)
	return rep, nil
}
