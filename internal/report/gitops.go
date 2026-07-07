package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// GitOpsAnnotations writes findings as GitHub Actions workflow-command
// annotations (::error / ::warning / ::notice), so a CI step surfaces each
// finding inline on the pull request without extra tooling. This is the
// shift-left "gate in the PR" surface that complements SARIF code-scanning and
// the admission webhook (one coherent policy story — see docs/shift-left.md).
//
// Deterministic: findings are already engine-sorted; severity maps to the
// annotation level. Offline manifests carry no file/line, so annotations are
// emitted without a file anchor (they appear at the top of the PR check).
func GitOpsAnnotations(w io.Writer, r api.Report) error {
	for _, f := range r.Findings {
		loc := f.Resource.Name
		if f.Resource.Namespace != "" {
			loc = f.Resource.Namespace + "/" + f.Resource.Name
		}
		msg := fmt.Sprintf("%s %s — %s", f.Resource.Kind, loc, f.Remediation.Summary)
		if _, err := fmt.Fprintf(w, "::%s title=%s %s::%s\n",
			annotationLevel(f.Severity), f.ID, escapeProp(f.Title), escapeData(msg)); err != nil {
			return err
		}
	}
	// A concise summary line (also a notice) so the PR check shows the headline
	// even when every finding is folded away.
	counts := map[api.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	if _, err := fmt.Fprintf(w, "::notice title=KubeGuard::%d findings — critical=%d high=%d medium=%d low=%d (indicative; not a certification)\n",
		len(r.Findings), counts[api.SeverityCritical], counts[api.SeverityHigh], counts[api.SeverityMedium], counts[api.SeverityLow]); err != nil {
		return err
	}
	return nil
}

func annotationLevel(s api.Severity) string {
	switch s {
	case api.SeverityCritical, api.SeverityHigh:
		return "error"
	case api.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

// escapeProp/escapeData apply GitHub's workflow-command escaping so titles and
// messages can't break out of the annotation syntax.
func escapeProp(s string) string {
	// Property values escape %, \r, \n, :, and ,. Escape % first.
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return r.Replace(s)
}

func escapeData(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}
