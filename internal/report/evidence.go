package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// EvidenceJSON writes one machine-readable evidence pack as indented JSON with
// stable key order, deterministic for a given report.
func EvidenceJSON(w io.Writer, ep api.EvidencePack) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ep); err != nil {
		return fmt.Errorf("encode evidence json: %w", err)
	}
	return nil
}

// techniques returns the MITRE ATT&CK technique ids attached to a finding, in
// authored order (refs are deterministic per check).
func techniques(refs []api.ControlRef) []string {
	var ids []string
	for _, r := range refs {
		if r.Framework == "ATT&CK" {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

var evidenceFuncs = template.FuncMap{
	"mulpct":     func(f float64) float64 { return f * 100 },
	"join":       func(s []string) string { return joinComma(s) },
	"techniques": techniques,
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// EvidenceHTML writes a self-contained, offline auditor evidence pack for one
// framework: every assessed control, its mapped checks, the breaching findings
// (redacted evidence, ATT&CK techniques, remediation), the breached/passed/
// assessed counts, pass rate, and the indicative-mapping disclaimer. No external
// resources are referenced and no secret values are emitted.
func EvidenceHTML(w io.Writer, ep api.EvidencePack) error {
	tmpl, err := template.New("evidence").Funcs(evidenceFuncs).Parse(evidenceTemplate)
	if err != nil {
		return fmt.Errorf("parse evidence template: %w", err)
	}
	if err := tmpl.Execute(w, ep); err != nil {
		return fmt.Errorf("render evidence html: %w", err)
	}
	return nil
}

const evidenceTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KubeGuard Evidence — {{.Framework}}</title>
<style>
:root{--bg:#0f1419;--panel:#1a2029;--fg:#e6e6e6;--mut:#8a93a0;--line:#2a323d;
--crit:#ff5c5c;--high:#ff9d5c;--med:#ffd05c;--low:#5cc8ff;--ok:#5cd28a}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:18px 24px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:18px}.sub{color:var(--mut);font-size:12px;margin-top:4px}
main{padding:24px;max-width:1000px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px}
.ctrl{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px}
.ctrl h3{margin:0 0 6px;font-size:15px}
.tag{font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 7px;border-radius:4px;color:#0f1419}
.t-breached{background:var(--crit)}.t-passed{background:var(--ok)}
.maps{color:var(--mut);font-size:12px;margin:6px 0}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 7px;border-radius:4px;color:#0f1419}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}.s-medium{background:var(--med)}.s-low{background:var(--low)}.s-info{background:var(--low)}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{background:#11161d;border:1px solid var(--line);border-radius:6px;padding:6px;margin-top:6px;overflow:auto}
.disc{color:var(--mut);font-size:12px;margin-top:10px}
.ev{color:var(--mut);font-size:12px}
</style></head><body>
<header><h1>KubeGuard Evidence Pack — {{.Framework}}{{if .Version}} <span class="sub">v{{.Version}}</span>{{end}}</h1>
<div class="sub">source: {{.Source}} · profile: {{.Profile}} · generated: {{.GeneratedAt}}</div></header>
<main>
<div class="cards">
<div class="card"><div class="n">{{.Assessed}}</div><div class="l">Assessed</div></div>
<div class="card"><div class="n" style="color:var(--crit)">{{.Breached}}</div><div class="l">Breached</div></div>
<div class="card"><div class="n" style="color:var(--ok)">{{.Passed}}</div><div class="l">Passed</div></div>
<div class="card"><div class="n">{{printf "%.0f%%" (mulpct .PassRate)}}</div><div class="l">Pass rate</div></div>
</div>
<p class="disc">{{.Breached}} breached of {{.Assessed}} assessed · {{.Passed}} passed of {{.Assessed}} assessed. {{.Disclaimer}}</p>
{{if not .Controls}}<p class="disc">No controls assessed for this framework against the scanned input.</p>{{end}}
{{range .Controls}}
<div class="ctrl">
<h3>{{if .Breached}}<span class="tag t-breached">breached</span>{{else}}<span class="tag t-passed">passed</span>{{end}} {{.ControlID}} — {{.Title}}</h3>
<div class="maps">Mapped checks: {{join .MapsTo}}</div>
{{if .Findings}}
<table><thead><tr><th>Severity</th><th>Check</th><th>Resource</th><th>ATT&CK</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>
{{range .Findings}}<tr>
<td><span class="sev s-{{.Severity}}">{{.Severity}}</span></td>
<td>{{.ID}}<br><span class="ev">{{.Title}}</span></td>
<td>{{.Resource.Kind}} {{.Resource.Namespace}}/{{.Resource.Name}}</td>
<td>{{join (techniques .Refs)}}</td>
<td class="ev">{{range .Evidence}}<div><code>{{.Path}}</code>{{if .Value}}: {{.Value}}{{end}}</div>{{end}}</td>
<td class="ev">{{.Remediation.Summary}}{{if .Remediation.Snippet}}<pre>{{.Remediation.Snippet}}</pre>{{end}}</td>
</tr>{{end}}
</tbody></table>
{{else}}<div class="ev">No findings — every mapped check passed against the scanned input.</div>{{end}}
</div>
{{end}}
<p class="disc">Evidence shows redacted field paths only — never secret values. Indicative control mapping; pass rate is passed of assessed.</p>
</main>
</body></html>`
