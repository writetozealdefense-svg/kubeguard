package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/pkg/api"
)

var htmlFuncs = template.FuncMap{
	"mulpct": func(f float64) float64 { return f * 100 },
	"join":   func(s []string) string { return strings.Join(s, ", ") },
	"add":    func(a, b int) int { return a + b },
}

type trendPoint struct {
	X, Y  float64
	Pct   string
	Label string
}

type htmlData struct {
	Report     api.Report
	SevCounts  map[string]int
	TrendLine  string
	TrendDots  []trendPoint
	HasHistory bool
	NodeChains [][]string // per-path capability chain
}

// HTML writes a self-contained, offline dashboard (Overview / Compliance /
// Attack-Paths / Findings) with an SVG pass-rate trend and clickable path nodes
// (ARCHITECTURE.md §10.1). No external resources are referenced.
func HTML(w io.Writer, r api.Report, hist []history.Record) error {
	data := htmlData{
		Report:    r,
		SevCounts: map[string]int{},
	}
	for _, f := range r.Findings {
		data.SevCounts[string(f.Severity)]++
	}
	for _, p := range r.Paths {
		chain := make([]string, 0, len(p.Hops)+1)
		if len(p.Hops) > 0 {
			chain = append(chain, string(p.Hops[0].From))
			for _, h := range p.Hops {
				chain = append(chain, string(h.To))
			}
		}
		data.NodeChains = append(data.NodeChains, chain)
	}
	buildTrend(&data, hist)

	tmpl, err := template.New("dashboard").Funcs(htmlFuncs).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}
	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}

func buildTrend(d *htmlData, hist []history.Record) {
	if len(hist) == 0 {
		return
	}
	d.HasHistory = true
	const w, h = 600.0, 160.0
	const padX, padY = 30.0, 20.0
	innerW, innerH := w-2*padX, h-2*padY
	n := len(hist)
	line := ""
	for i, rec := range hist {
		x := padX
		if n > 1 {
			x = padX + innerW*float64(i)/float64(n-1)
		}
		y := padY + innerH*(1-rec.OverallPassRate)
		line += fmt.Sprintf("%.1f,%.1f ", x, y)
		d.TrendDots = append(d.TrendDots, trendPoint{
			X: x, Y: y,
			Pct:   fmt.Sprintf("%.0f%%", rec.OverallPassRate*100),
			Label: rec.Source,
		})
	}
	d.TrendLine = line
}

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KubeGuard Report</title>
<style>
:root{--bg:#0f1419;--panel:#1a2029;--fg:#e6e6e6;--mut:#8a93a0;--line:#2a323d;
--crit:#ff5c5c;--high:#ff9d5c;--med:#ffd05c;--low:#5cc8ff;--ok:#5cd28a}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:18px 24px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:18px}.sub{color:var(--mut);font-size:12px;margin-top:4px}
nav{display:flex;gap:4px;padding:0 16px;border-bottom:1px solid var(--line);background:var(--panel)}
nav button{background:none;border:0;color:var(--mut);padding:12px 16px;cursor:pointer;font-size:14px;border-bottom:2px solid transparent}
nav button.active{color:var(--fg);border-bottom-color:var(--low)}
main{padding:24px;max-width:1000px;margin:0 auto}.tab{display:none}.tab.active{display:block}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 7px;border-radius:4px;color:#0f1419}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}.s-medium{background:var(--med)}.s-low{background:var(--low)}
.path{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px}
.chain{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:10px 0}
.node{background:#222c38;border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer;font-size:12px}
.node:hover{border-color:var(--low)}.arrow{color:var(--mut)}
.hopdetail{display:none;border-left:2px solid var(--low);padding:6px 12px;margin:6px 0;color:var(--mut)}
.hopdetail.show{display:block}.disc{color:var(--mut);font-size:12px;margin-top:10px}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;width:160px;display:inline-block;vertical-align:middle}
.bar>i{display:block;height:100%;background:var(--ok)}
svg{background:var(--panel);border:1px solid var(--line);border-radius:8px}
</style></head><body>
<header><h1>KubeGuard Report</h1>
<div class="sub">source: {{.Report.Source}} · profile: {{.Report.Profile}} · generated: {{.Report.GeneratedAt}}</div></header>
<nav>
<button class="tab-btn active" data-t="overview">Overview</button>
<button class="tab-btn" data-t="compliance">Compliance</button>
<button class="tab-btn" data-t="paths">Attack Paths</button>
<button class="tab-btn" data-t="findings">Findings</button>
</nav><main>

<section id="overview" class="tab active">
<div class="cards">
<div class="card"><div class="n">{{len .Report.Findings}}</div><div class="l">Findings</div></div>
<div class="card"><div class="n" style="color:var(--crit)">{{index .SevCounts "critical"}}</div><div class="l">Critical</div></div>
<div class="card"><div class="n" style="color:var(--high)">{{index .SevCounts "high"}}</div><div class="l">High</div></div>
<div class="card"><div class="n">{{len .Report.Paths}}</div><div class="l">Attack paths</div></div>
<div class="card"><div class="n">{{printf "%.0f%%" (mulpct .Report.Posture.OverallPassRate)}}</div><div class="l">Control pass</div></div>
</div>
{{if .HasHistory}}<h3>Control-pass trend</h3>
<svg viewBox="0 0 600 160" width="600" height="160">
<polyline fill="none" stroke="#5cd28a" stroke-width="2" points="{{.TrendLine}}"/>
{{range .TrendDots}}<circle cx="{{.X}}" cy="{{.Y}}" r="3" fill="#5cd28a"><title>{{.Pct}} — {{.Label}}</title></circle>{{end}}
</svg>{{else}}<p class="disc">No history yet — scan with --history to build a trend.</p>{{end}}
</section>

<section id="compliance" class="tab">
<table><thead><tr><th>Framework</th><th>Breached / Assessed</th><th>Pass</th></tr></thead><tbody>
{{range .Report.Compliance}}<tr><td>{{.Framework}} {{if .Version}}<span class="disc">v{{.Version}}</span>{{end}}</td>
<td>{{.Breached}} of {{.Assessed}}</td>
<td><span class="bar"><i style="width:{{printf "%.0f%%" (mulpct .PassRate)}}"></i></span> {{printf "%.0f%%" (mulpct .PassRate)}}</td></tr>
{{range .Breaches}}<tr><td class="disc" style="padding-left:24px">↳ {{.ControlID}} {{.Title}}</td><td class="disc" colspan="2">{{join .Findings}}</td></tr>{{end}}
{{end}}</tbody></table>
<p class="disc">Indicative control mapping only; not a certification or audit. Pass rate is shown as passed of assessed.</p>
</section>

<section id="paths" class="tab">
{{if not .Report.Paths}}<p class="disc">No attack paths.</p>{{end}}
{{range $pi, $p := .Report.Paths}}
<div class="path"><span class="sev s-{{$p.Severity}}">{{$p.Severity}}</span> <strong>{{$p.Title}}</strong>
<div class="chain">{{range $i, $cap := index $.NodeChains $pi}}{{if $i}}<span class="arrow">→</span>{{end}}<span class="node" onclick="hop('{{$pi}}',{{$i}})">{{$cap}}</span>{{end}}</div>
{{range $hi, $h := $p.Hops}}<div class="hopdetail" id="h-{{$pi}}-{{add $hi 1}}"><strong>{{$h.From}} → {{$h.To}}</strong> · enabled by {{$h.EnabledBy}} · ATT&CK {{join $h.Technique}}<br>{{$h.Narrative}}</div>{{end}}
<div class="disc">{{$p.Summary}}</div></div>
{{end}}
</section>

<section id="findings" class="tab">
<table><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Resource</th><th>Remediation</th></tr></thead><tbody>
{{range .Report.Findings}}<tr><td><span class="sev s-{{.Severity}}">{{.Severity}}</span></td><td>{{.ID}}</td><td>{{.Title}}</td>
<td>{{.Resource.Kind}} {{.Resource.Namespace}}/{{.Resource.Name}}</td>
<td class="disc">{{.Remediation.Summary}}{{if .Remediation.Snippet}}<pre style="background:#11161d;border:1px solid var(--line);border-radius:6px;padding:6px;margin-top:6px;overflow:auto">{{.Remediation.Snippet}}</pre>{{end}}</td></tr>{{end}}
</tbody></table>
</section>
</main>
<script>
document.querySelectorAll('.tab-btn').forEach(function(b){b.onclick=function(){
document.querySelectorAll('.tab-btn').forEach(function(x){x.classList.remove('active')});
document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
b.classList.add('active');document.getElementById(b.dataset.t).classList.add('active');};});
function hop(pi,i){var el=document.getElementById('h-'+pi+'-'+i);if(el){el.classList.toggle('show');}}
</script>
</body></html>`
