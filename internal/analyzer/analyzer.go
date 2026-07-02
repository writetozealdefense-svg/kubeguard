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
	"github.com/kubeguard/kubeguard/pkg/api"
)

// Analyze builds the graph, runs the checks, chains attack paths, and evaluates
// compliance. The caller sets Report.GeneratedAt and Report.Source.
func Analyze(resources []model.Resource, profileName string, assumeBreach bool) (api.Report, error) {
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
	paths := attack.BuildPaths(g, assumeBreach)
	frameworks := compliance.EvaluateAll(packs, profile.RunnableIDs(), compliance.FiredChecks(findings))

	coverage := g.Coverage()
	return api.Report{
		Profile:    profile.Name,
		Findings:   findings,
		Paths:      paths,
		Posture:    compliance.Summarize(findings, paths, frameworks),
		Compliance: frameworks,
		Coverage:   &coverage,
	}, nil
}
