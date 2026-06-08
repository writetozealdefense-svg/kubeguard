package report

import (
	"fmt"
	"io"

	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const sarifToolURI = "https://github.com/kubeguard/kubeguard"

func sarifLevel(s api.Severity) string {
	switch s {
	case api.SeverityCritical, api.SeverityHigh:
		return "error"
	case api.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes findings as a SARIF 2.1.0 document (ARCHITECTURE.md §10.1).
func SARIF(w io.Writer, r api.Report) error {
	doc, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("init sarif: %w", err)
	}
	run := sarif.NewRunWithInformationURI("KubeGuard", sarifToolURI)

	// One rule per check id that produced a finding (stable order: findings are
	// already sorted deterministically).
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		run.AddRule(f.ID).
			WithName(f.Title).
			WithDescription(f.Remediation.Summary).
			WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(sarifLevel(f.Severity)))
	}

	for _, f := range r.Findings {
		fqn := resourceFQN(f.Resource)
		loc := sarif.NewLocation().WithLogicalLocations([]*sarif.LogicalLocation{
			sarif.NewLogicalLocation().WithName(f.Resource.Name).WithKind(f.Resource.Kind).WithFullyQualifiedName(fqn),
		})
		run.CreateResultForRule(f.ID).
			WithLevel(sarifLevel(f.Severity)).
			WithMessage(sarif.NewTextMessage(fmt.Sprintf("%s — %s (%s)", f.Title, fqn, f.Severity))).
			WithLocations([]*sarif.Location{loc})
	}

	doc.AddRun(run)
	if err := doc.PrettyWrite(w); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

func resourceFQN(r api.ResourceRef) string {
	if r.Namespace != "" {
		return r.Namespace + "/" + r.Kind + "/" + r.Name
	}
	return r.Kind + "/" + r.Name
}
