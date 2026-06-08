package dashboard

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus collectors for the dashboard (P3). Each API owns
// its own registry so instances don't collide (and tests stay isolated).
type Metrics struct {
	reg          *prometheus.Registry
	httpDuration *prometheus.HistogramVec
	scanDuration *prometheus.HistogramVec
	scansTotal   *prometheus.CounterVec
	findings     *prometheus.GaugeVec
	passRate     *prometheus.GaugeVec
}

func newMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubeguard_dashboard_http_request_duration_seconds",
			Help:    "Dashboard API request latency.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"route", "method", "status"}),
		scanDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kubeguard_dashboard_scan_duration_seconds",
			Help:    "Time to run a scan, by cluster and result.",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"cluster", "result"}),
		scansTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kubeguard_dashboard_scans_total",
			Help: "Total scans run, by cluster and result.",
		}, []string{"cluster", "result"}),
		findings: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kubeguard_dashboard_findings",
			Help: "Findings in the latest scan, by cluster and severity.",
		}, []string{"cluster", "severity"}),
		passRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kubeguard_dashboard_compliance_pass_rate",
			Help: "Compliance pass rate (passed of assessed) by cluster and framework.",
		}, []string{"cluster", "framework"}),
	}
	m.reg.MustRegister(m.httpDuration, m.scanDuration, m.scansTotal, m.findings, m.passRate)
	return m
}

// middleware records request latency + status for every route.
func (m *Metrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		// chi fills the matched pattern during routing; falling back to the raw
		// path keeps cardinality bounded for known routes.
		route := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
			route = rctx.RoutePattern()
		}
		m.httpDuration.WithLabelValues(route, r.Method, strconv.Itoa(ww.Status())).
			Observe(time.Since(start).Seconds())
	})
}

// recordScan records scan duration + count and refreshes the posture gauges.
func (m *Metrics) recordScan(cluster, result string, dur time.Duration, rep api.Report) {
	m.scanDuration.WithLabelValues(cluster, result).Observe(dur.Seconds())
	m.scansTotal.WithLabelValues(cluster, result).Inc()
	if result != "success" {
		return
	}
	for _, sev := range []api.Severity{api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow, api.SeverityInfo} {
		m.findings.WithLabelValues(cluster, string(sev)).Set(float64(rep.Posture.BySeverity[sev]))
	}
	for _, fw := range rep.Compliance {
		m.passRate.WithLabelValues(cluster, fw.Framework).Set(fw.PassRate)
	}
}
