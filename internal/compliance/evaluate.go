package compliance

import (
	"math"
	"sort"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// Evaluate computes posture for one pack (ARCHITECTURE.md §9.2). Honest
// denominator: a control is assessed only if EVERY check it maps to actually
// ran; a control is breached if any mapped check produced a finding.
func (p Pack) Evaluate(executed, fired map[string]bool) api.FrameworkResult {
	res := api.FrameworkResult{
		Framework:  p.Title,
		Version:    p.Version,
		Disclaimer: p.Disclaimer,
	}
	for _, c := range p.Controls {
		if !c.Assessable || !allRan(c.MapsTo, executed) {
			continue
		}
		res.Assessed++
		var offending []string
		for _, id := range c.MapsTo {
			if fired[id] {
				offending = append(offending, id)
			}
		}
		if len(offending) > 0 {
			res.Breached++
			sort.Strings(offending)
			res.Breaches = append(res.Breaches, api.ControlBreach{
				ControlID: c.ID,
				Title:     c.Title,
				Findings:  offending,
			})
		}
	}
	res.Passed = res.Assessed - res.Breached
	if res.Assessed > 0 {
		res.PassRate = round4(float64(res.Passed) / float64(res.Assessed))
	}
	return res
}

// EvaluateAll evaluates every pack in order.
func EvaluateAll(packs []Pack, executed, fired map[string]bool) []api.FrameworkResult {
	out := make([]api.FrameworkResult, 0, len(packs))
	for _, p := range packs {
		out = append(out, p.Evaluate(executed, fired))
	}
	return out
}

// Summarize aggregates findings, paths, and framework results into a posture.
func Summarize(findings []api.Finding, paths []api.AttackPath, results []api.FrameworkResult) api.PostureSummary {
	s := api.PostureSummary{TotalFindings: len(findings), BySeverity: map[api.Severity]int{}}
	for _, f := range findings {
		s.BySeverity[f.Severity]++
	}
	for _, p := range paths {
		if p.Severity == api.SeverityCritical {
			s.CriticalPaths++
		}
	}
	for _, r := range results {
		s.ControlsAssessed += r.Assessed
		s.ControlsBreached += r.Breached
	}
	if s.ControlsAssessed > 0 {
		passed := s.ControlsAssessed - s.ControlsBreached
		s.OverallPassRate = round4(float64(passed) / float64(s.ControlsAssessed))
	}
	return s
}

// FiredChecks returns the set of check ids that produced at least one finding.
func FiredChecks(findings []api.Finding) map[string]bool {
	m := make(map[string]bool, len(findings))
	for _, f := range findings {
		m[f.ID] = true
	}
	return m
}

func allRan(ids []string, executed map[string]bool) bool {
	for _, id := range ids {
		if !executed[id] {
			return false
		}
	}
	return true
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
