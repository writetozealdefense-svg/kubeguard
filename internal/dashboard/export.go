package dashboard

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
	"github.com/kubeguard/kubeguard/internal/report"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// Brand carries the co-branding for engagement reports (e.g. ZealDefense). The
// tenant slot is filled from the authenticated principal; Title/Logo are
// configured on the API.
type Brand struct {
	Title  string // e.g. "ZealDefense" — defaults to "KubeGuard" if empty
	Tenant string
}

// honest-metrics disclaimer carried on every exported report.
const reportDisclaimer = "Indicative control mapping only — not a certification or audit. " +
	"Compliance figures are reported as breached/passed of assessed."

// ExportSARIF reuses the engine's validated SARIF 2.1.0 reporter.
func ExportSARIF(rep api.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, rep); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExportCSV emits the findings as CSV (id, severity, category, resource, title,
// frameworks). Secret values never appear — only finding metadata.
func ExportCSV(rep api.Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "severity", "category", "namespace", "resource", "title", "frameworks"})
	for _, f := range rep.Findings {
		fws := make([]string, 0, len(f.Refs))
		for _, r := range f.Refs {
			fws = append(fws, fmt.Sprintf("%s %s", r.Framework, r.ID))
		}
		res := f.Resource.Kind + " " + f.Resource.Name
		if err := w.Write([]string{
			f.ID, string(f.Severity), f.Category, f.Resource.Namespace, res, f.Title, strings.Join(fws, "; "),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// ExportPDF renders a co-branded engagement report: a brand/tenant header, the
// honest posture summary (with assessed denominators + disclaimer), the
// per-framework compliance breach table, and the attack-path chain narrative.
func ExportPDF(rep api.Report, brand Brand) ([]byte, error) {
	title := brand.Title
	if title == "" {
		title = "KubeGuard"
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false) // keep text legible in the byte stream (testable)
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// Co-branded header (logo slot = brand title + tenant).
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, fmt.Sprintf("%s — Kubernetes Security Report", title), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("Tenant: %s    Source: %s    Generated: %s", brand.Tenant, rep.Source, rep.GeneratedAt), "", 1, "L", false, 0, "")
	pdf.Ln(3)

	// Posture summary (honest denominators).
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 8, "Posture summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	p := rep.Posture
	passed := p.ControlsAssessed - p.ControlsBreached
	pdf.MultiCell(0, 5, fmt.Sprintf(
		"Total findings: %d (critical %d, high %d, medium %d, low %d)\n"+
			"Attack paths: %d\nOverall control pass: %d of %d assessed (%d%%)",
		p.TotalFindings, p.BySeverity[api.SeverityCritical], p.BySeverity[api.SeverityHigh],
		p.BySeverity[api.SeverityMedium], p.BySeverity[api.SeverityLow], p.CriticalPaths,
		passed, p.ControlsAssessed, pctInt(passed, p.ControlsAssessed)), "", "L", false)
	pdf.Ln(2)

	// Compliance breach table (breached of assessed).
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 8, "Compliance (indicative mapping)", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	for _, fw := range rep.Compliance {
		pdf.CellFormat(0, 5, fmt.Sprintf("%s: %d breached of %d assessed (%d%% pass)",
			fw.Framework, fw.Breached, fw.Assessed, pctInt(fw.Passed, fw.Assessed)), "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)

	// Attack-path chain narrative (descriptive — never a runnable exploit).
	if len(rep.Paths) > 0 {
		pdf.SetFont("Helvetica", "B", 13)
		pdf.CellFormat(0, 8, "Attack paths", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		for _, path := range rep.Paths {
			pdf.SetFont("Helvetica", "B", 10)
			pdf.MultiCell(0, 5, fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(path.Severity)), path.ID, path.Title), "", "L", false)
			pdf.SetFont("Helvetica", "", 9)
			for _, h := range path.Hops {
				pdf.MultiCell(0, 4.5, fmt.Sprintf("  %d. %s -> %s  [%s %s]  %s",
					h.Order, h.From, h.To, h.EnabledBy, strings.Join(h.Technique, ","), h.Narrative), "", "L", false)
			}
			pdf.Ln(1)
		}
	}

	// Honest-metrics disclaimer footer.
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.MultiCell(0, 4, reportDisclaimer, "", "L", false)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func pctInt(n, d int) int {
	if d == 0 {
		return 0
	}
	return n * 100 / d
}
