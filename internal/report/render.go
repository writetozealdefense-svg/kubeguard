package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// JSON writes the report as indented JSON with stable key order.
func JSON(w io.Writer, r api.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}
	return nil
}

// ANSI colours, applied only when color is true.
const (
	ansiReset   = "\033[0m"
	ansiRed     = "\033[31m"
	ansiMagenta = "\033[35m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
	ansiBold    = "\033[1m"
)

func sevColor(s api.Severity) string {
	switch s {
	case api.SeverityCritical:
		return ansiBold + ansiRed
	case api.SeverityHigh:
		return ansiMagenta
	case api.SeverityMedium:
		return ansiYellow
	default:
		return ansiCyan
	}
}

func colorize(s string, code string, on bool) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

// Console writes a human summary grouped by the (already sorted) finding order.
// color enables ANSI colour (callers pass true only for a TTY).
func Console(w io.Writer, r api.Report, color bool) error {
	counts := map[api.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	if _, err := fmt.Fprintf(w, "KubeGuard scan — source=%s profile=%s\n\n", r.Source, r.Profile); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "No findings. 0 issues across assessed checks."); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		loc := f.Resource.Name
		if f.Resource.Namespace != "" {
			loc = f.Resource.Namespace + "/" + f.Resource.Name
		}
		tag := colorize(fmt.Sprintf("[%-8s]", f.Severity), sevColor(f.Severity), color)
		if _, err := fmt.Fprintf(w, "%s %s  %s  (%s %s)\n", tag, f.ID, f.Title, f.Resource.Kind, loc); err != nil {
			return err
		}
	}
	if len(r.Findings) > 0 {
		if _, err := fmt.Fprintf(w, "\nSummary: %d findings — critical=%d high=%d medium=%d low=%d\n",
			len(r.Findings), counts[api.SeverityCritical], counts[api.SeverityHigh],
			counts[api.SeverityMedium], counts[api.SeverityLow]); err != nil {
			return err
		}
	}
	if err := consoleCoverage(w, r.Coverage); err != nil {
		return err
	}
	if err := consolePaths(w, r.Paths, color); err != nil {
		return err
	}
	return consoleCompliance(w, r.Compliance)
}

// consoleCoverage prints the honest assessment-coverage line: how much of the
// discovered inventory the engine actually assessed. Nil coverage prints
// nothing (older producers), so the line is additive.
func consoleCoverage(w io.Writer, cov *api.CoverageBreakdown) error {
	if cov == nil || cov.Discovered == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nAssessment coverage: %d of %d resources assessed (%.0f%%); %d skipped\n",
		cov.Assessable, cov.Discovered, cov.Rate*100, cov.Skipped); err != nil {
		return err
	}
	if len(cov.SkippedByKind) > 0 {
		kinds := make([]string, 0, len(cov.SkippedByKind))
		for k := range cov.SkippedByKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		parts := make([]string, 0, len(kinds))
		for _, k := range kinds {
			parts = append(parts, fmt.Sprintf("%s×%d", k, cov.SkippedByKind[k]))
		}
		if _, err := fmt.Fprintf(w, "  skipped kinds (no built-in check): %s\n", strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func consolePaths(w io.Writer, paths []api.AttackPath, color bool) error {
	if len(paths) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nAttack paths: %d\n", len(paths)); err != nil {
		return err
	}
	for _, p := range paths {
		tag := colorize(fmt.Sprintf("[%-8s]", p.Severity), sevColor(p.Severity), color)
		if _, err := fmt.Fprintf(w, "\n%s %s  %s\n", tag, p.ID, p.Title); err != nil {
			return err
		}
		for _, h := range p.Hops {
			if _, err := fmt.Fprintf(w, "  %d. %s → %s  [%s %s]  %s\n",
				h.Order, h.From, h.To, h.EnabledBy, strings.Join(h.Technique, ","), h.Narrative); err != nil {
				return err
			}
		}
	}
	return nil
}

func consoleCompliance(w io.Writer, results []api.FrameworkResult) error {
	if len(results) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nCompliance (indicative mapping — breached of assessed):\n"); err != nil {
		return err
	}
	for _, r := range results {
		pct := "n/a"
		if r.Assessed > 0 {
			pct = fmt.Sprintf("%.0f%%", r.PassRate*100)
		}
		if _, err := fmt.Fprintf(w, "  %-45s %d breached of %d assessed (%s pass)\n",
			r.Framework, r.Breached, r.Assessed, pct); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "  Note: indicative control mapping only; not a certification or audit.")
	return err
}
