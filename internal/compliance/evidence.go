package compliance

import (
	"sort"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// BuildEvidence builds one deterministic auditor evidence pack per framework.
// Each pack lists every assessed control (assessable, with all mapped checks
// run), the checks it maps to, and the full findings that breached it — reusing
// api.Finding so the redacted evidence, ATT&CK refs, and remediation travel with
// it. Controls that are not assessable, or whose mapped checks did not all run,
// are excluded from the denominator entirely (honest-metrics: never silently
// passed). The single rep.GeneratedAt is the only wall-clock timestamp.
func BuildEvidence(rep api.Report, packs []Pack, executed map[string]bool) []api.EvidencePack {
	byCheck := make(map[string][]api.Finding, len(rep.Findings))
	for _, f := range rep.Findings {
		byCheck[f.ID] = append(byCheck[f.ID], f)
	}
	out := make([]api.EvidencePack, 0, len(packs))
	for _, p := range packs {
		ep := api.EvidencePack{
			GeneratedAt: rep.GeneratedAt,
			Source:      rep.Source,
			Profile:     rep.Profile,
			ID:          p.ID,
			Framework:   p.Title,
			Version:     p.Version,
			Disclaimer:  p.Disclaimer,
		}
		for _, c := range p.Controls {
			if !c.Assessable || !allRan(c.MapsTo, executed) {
				continue
			}
			ep.Assessed++
			mapped := append([]string(nil), c.MapsTo...)
			sort.Strings(mapped)
			var fs []api.Finding
			for _, id := range mapped {
				fs = append(fs, byCheck[id]...)
			}
			ctrl := api.EvidenceControl{
				ControlID: c.ID,
				Title:     c.Title,
				MapsTo:    mapped,
				Breached:  len(fs) > 0,
				Findings:  fs,
			}
			if ctrl.Breached {
				ep.Breached++
			}
			ep.Controls = append(ep.Controls, ctrl)
		}
		ep.Passed = ep.Assessed - ep.Breached
		if ep.Assessed > 0 {
			ep.PassRate = round4(float64(ep.Passed) / float64(ep.Assessed))
		}
		out = append(out, ep)
	}
	return out
}
